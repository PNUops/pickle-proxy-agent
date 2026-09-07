// Package config loads the proxy-agent configuration from the environment.
//
// Every value has a production default that matches the as-built LXC 100 layout;
// tests override the paths and binaries to point at temp dirs and fakes so nothing
// here needs a real nginx.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pnuops/pickle-proxy-agent/internal/render"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Listen is the TCP address the HTTP control server binds. Production binds
	// the vmbr1 address only (172.30.1.10) so the agent is never reachable off the
	// internal bridge; there is no DNAT to it.
	Listen string

	// Token is the shared bearer token (PICKLE_PROXY_AGENT_TOKEN). Empty is a fatal
	// misconfiguration — the auth layer fails closed when it is blank.
	Token string

	// AllowedSources is the set of source IPs permitted to call the agent. Defaults
	// to pickle-api (172.30.1.20); an empty set denies everyone (fail closed).
	AllowedSources []string

	// NginxDir is the agent-owned include directory. The agent owns exactly the
	// *.conf files here and never touches anything else in the nginx tree (the
	// opus.pusan.ac.kr config is inviolable).
	NginxDir string

	// StateFile persists the last-applied generation per FQDN so a restart cannot
	// forget what it applied and accept a stale request.
	StateFile string

	// NginxBin / reload+test are split so tests can inject a fake binary.
	NginxBin string

	// LECertRef is the exact certRef value pickle-api uses for custom domains.
	// Anything that is neither this nor a wildcard ref is refused: an unknown ref
	// almost certainly means the two sides are on different contract versions,
	// and the old catch-all behaviour would have issued a public certificate for
	// a platform subdomain instead of saying so.
	LECertRef string

	// WildcardCerts is the wildcard certificate material per platform root domain,
	// keyed by the root ("pusan.dev"). The operator issues and installs it; the
	// agent only consumes the paths it is given. Several roots can be served at
	// once, each with its own certificate; a route naming a root that is absent is
	// refused rather than rendered with another root's pair.
	WildcardCerts map[string]render.CertPair

	// HTTPSListen is the internal HTTPS listen address for terminated vhosts. The
	// stream{} block owns :443 and forwards non-passthrough SNIs here.
	HTTPSListen string

	// SiteLimits renders the default per-site request and connection limits into
	// every published vhost (PICKLE_PROXY_AGENT_SITE_LIMITS, default on). Off is
	// for a host whose base nginx config does not declare the zones the limits
	// name: a vhost referencing a zone that does not exist fails `nginx -t`, and
	// that failure rejects the entire config, not the one file.
	SiteLimits bool

	// Custom-domain / certbot settings.
	CertbotBin   string
	Webroot      string
	LEDir        string // /etc/letsencrypt/live/<fqdn>/{fullchain,privkey}.pem
	CertbotEmail string

	// RateLimitPerMin bounds calls per key (FQDN for /apply, source-IP otherwise).
	// 0 disables the limiter (used in tests).
	RateLimitPerMin int

	// ExecTimeout bounds any nginx/certbot subprocess. A measured HTTP-01 issuance
	// takes about 40s, so the bound has to leave room for a slow ACME round trip
	// rather than cut issuance off mid-flight.
	ExecTimeout time.Duration
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// Load reads the configuration from the environment, applying production defaults.
// It returns an error for a missing token and for configuration it cannot read at
// all: a malformed wildcard entry, or an on/off value spelled some other way.
func Load() (Config, error) {
	c := Config{
		Listen:          env("PICKLE_PROXY_AGENT_LISTEN", "172.30.1.10:9443"),
		Token:           os.Getenv("PICKLE_PROXY_AGENT_TOKEN"),
		AllowedSources:  splitList(env("PICKLE_PROXY_AGENT_ALLOWED_SRC", "172.30.1.20")),
		NginxDir:        env("PICKLE_PROXY_AGENT_NGINX_DIR", "/etc/nginx/pickle.d"),
		StateFile:       env("PICKLE_PROXY_AGENT_STATE_FILE", "/var/lib/pickle-proxy-agent/state.json"),
		NginxBin:        env("PICKLE_PROXY_AGENT_NGINX_BIN", "nginx"),
		HTTPSListen:     env("PICKLE_PROXY_AGENT_HTTPS_LISTEN", "127.0.0.1:8443"),
		LECertRef:       env("PICKLE_PROXY_AGENT_LE_CERT_REF", "letsencrypt"),
		CertbotBin:      env("PICKLE_PROXY_AGENT_CERTBOT_BIN", "certbot"),
		Webroot:         env("PICKLE_PROXY_AGENT_WEBROOT", "/var/www/certbot"),
		LEDir:           env("PICKLE_PROXY_AGENT_LE_DIR", "/etc/letsencrypt/live"),
		CertbotEmail:    env("PICKLE_PROXY_AGENT_CERTBOT_EMAIL", ""),
		RateLimitPerMin: 600,
		ExecTimeout:     180 * time.Second,
	}
	wildcards, err := parseWildcardCerts(os.Getenv("PICKLE_PROXY_AGENT_WILDCARD_CERTS"))
	if err != nil {
		return Config{}, err
	}
	c.WildcardCerts = wildcards
	siteLimits, err := parseOnOff("PICKLE_PROXY_AGENT_SITE_LIMITS", true)
	if err != nil {
		return Config{}, err
	}
	c.SiteLimits = siteLimits
	switch t := strings.TrimSpace(c.Token); t {
	case "":
		return Config{}, fmt.Errorf("PICKLE_PROXY_AGENT_TOKEN is required (empty token would leave the agent unauthenticated)")
	case "CHANGEME", "CHANGME":
		// Guard against booting with a template placeholder (an old deploy.sh wrote
		// the "CHANGME" typo); a well-known token is as bad as no token.
		return Config{}, fmt.Errorf("PICKLE_PROXY_AGENT_TOKEN is the placeholder %q; generate a real one (openssl rand -hex 32)", t)
	}
	return c, nil
}

// parseWildcardCerts reads PICKLE_PROXY_AGENT_WILDCARD_CERTS, a comma-separated
// list of "<root>=<certPath>:<keyPath>" entries — one per platform root domain:
//
//	pusan.dev=/etc/letsencrypt/live/pusan.dev/fullchain.pem:/etc/letsencrypt/live/pusan.dev/privkey.pem
//
// There is no default. A blank value yields an empty map, which is not fatal by
// itself (an agent serving only custom domains needs none) but makes every
// platform route fail at apply with a message naming the missing root — a loud,
// specific failure instead of a vhost quietly built on a path nobody set.
// Malformed entries ARE fatal: a typo that silently dropped one root would take
// its subdomains down at the next apply, long after the restart that caused it.
func parseWildcardCerts(s string) (map[string]render.CertPair, error) {
	out := map[string]render.CertPair{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		root, pair, ok := strings.Cut(entry, "=")
		root = strings.TrimSpace(root)
		if !ok || root == "" {
			return nil, fmt.Errorf("PICKLE_PROXY_AGENT_WILDCARD_CERTS entry %q: want <root>=<cert>:<key>", entry)
		}
		certPath, keyPath, ok := strings.Cut(pair, ":")
		certPath, keyPath = strings.TrimSpace(certPath), strings.TrimSpace(keyPath)
		if !ok || certPath == "" || keyPath == "" {
			return nil, fmt.Errorf("PICKLE_PROXY_AGENT_WILDCARD_CERTS entry %q: want <root>=<cert>:<key>", entry)
		}
		if _, dup := out[root]; dup {
			return nil, fmt.Errorf("PICKLE_PROXY_AGENT_WILDCARD_CERTS lists root %q twice", root)
		}
		out[root] = render.CertPair{Cert: certPath, Key: keyPath}
	}
	return out, nil
}

// parseOnOff reads a boolean setting, accepting only the four spellings an env file
// is written with. An unset variable takes the default; a variable set to anything
// else, blank included, is fatal rather than read as the default. This one decides
// whether published sites carry a rate limit at all, and a typo that quietly turned
// it off would show up as an outage under load, long after the restart that caused it.
func parseOnOff(key string, def bool) (bool, error) {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true":
		return true, nil
	case "off", "false":
		return false, nil
	}
	return false, fmt.Errorf("%s is %q: want on or off (true/false also accepted)", key, raw)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
