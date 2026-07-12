package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

// authConfig is the fail-closed access policy: a wrong source or a bad token is
// rejected before any handler runs, mirroring the pickle-api /internal chain.
type authConfig struct {
	token          string
	allowedSources map[string]bool
}

func newAuth(token string, sources []string) authConfig {
	set := make(map[string]bool, len(sources))
	for _, s := range sources {
		set[s] = true
	}
	return authConfig{token: token, allowedSources: set}
}

// guard wraps a handler with the source-IP and bearer-token checks. Order: the
// source is checked first (network layer) so a disallowed peer never reaches token
// evaluation; then the token. Both must pass (defence in depth on top of the
// firewall). Every branch fails closed — an empty configured token or empty source
// allowlist denies everyone.
func (a authConfig) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.sourceAllowed(r.RemoteAddr) {
			writeProblem(w, http.StatusForbidden, "ACCESS_DENIED")
			return
		}
		if !a.tokenValid(r.Header.Get("Authorization")) {
			writeProblem(w, http.StatusUnauthorized, "AUTH_TOKEN_INVALID")
			return
		}
		next(w, r)
	}
}

func (a authConfig) sourceAllowed(remoteAddr string) bool {
	if len(a.allowedSources) == 0 {
		return false // fail closed: no allowlist means no access
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return a.allowedSources[host]
}

func (a authConfig) tokenValid(header string) bool {
	if strings.TrimSpace(a.token) == "" {
		return false // fail closed: misconfigured (empty) token authenticates nobody
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(header[len(prefix):])
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

func writeProblem(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, model.Problem{Code: code})
}
