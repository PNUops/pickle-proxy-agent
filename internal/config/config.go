// Package config loads the proxy-agent configuration from the environment.
//
// Every value has a production default that matches the as-built LXC 100 layout
// (docs/plan/01-architecture.md, 06-domains-tls.md); tests override the paths and
// binaries to point at temp dirs and fakes so nothing here needs a real nginx.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
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

	// TLS certificate material for the platform wildcard (Cloudflare Origin CA).
	WildcardCert string
	WildcardKey  string

	// HTTPSListen is the internal HTTPS listen address for terminated vhosts. The
	// stream{} block owns :443 and forwards non-passthrough SNIs here.
	HTTPSListen string

	// RealIPInclude, when non-empty, is emitted as `include <path>;` inside each
	// vhost so the operator-managed Cloudflare set_real_ip_from list is applied
	// without the agent having to own that file.
	RealIPInclude string

	// Custom-domain / certbot settings.
	CertbotBin   string
	Webroot      string
	LEDir        string // /etc/letsencrypt/live/<fqdn>/{fullchain,privkey}.pem
	CertbotEmail string

	// RateLimitPerMin bounds calls per key (FQDN for /apply, source-IP otherwise).
	// 0 disables the limiter (used in tests).
	RateLimitPerMin int

	// ExecTimeout bounds any nginx/certbot subprocess.
	ExecTimeout time.Duration
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// Load reads the configuration from the environment, applying production defaults.
// It returns an error only for values that cannot have a safe default (the token).
func Load() (Config, error) {
	c := Config{
		Listen:          env("PICKLE_PROXY_AGENT_LISTEN", "172.30.1.10:9443"),
		Token:           os.Getenv("PICKLE_PROXY_AGENT_TOKEN"),
		AllowedSources:  splitList(env("PICKLE_PROXY_AGENT_ALLOWED_SRC", "172.30.1.20")),
		NginxDir:        env("PICKLE_PROXY_AGENT_NGINX_DIR", "/etc/nginx/pickle.d"),
		StateFile:       env("PICKLE_PROXY_AGENT_STATE_FILE", "/var/lib/pickle-proxy-agent/state.json"),
		NginxBin:        env("PICKLE_PROXY_AGENT_NGINX_BIN", "nginx"),
		WildcardCert:    env("PICKLE_PROXY_AGENT_WILDCARD_CERT", "/etc/nginx/certs/origin/fullchain.pem"),
		WildcardKey:     env("PICKLE_PROXY_AGENT_WILDCARD_KEY", "/etc/nginx/certs/origin/privkey.pem"),
		HTTPSListen:     env("PICKLE_PROXY_AGENT_HTTPS_LISTEN", "127.0.0.1:8443"),
		RealIPInclude:   env("PICKLE_PROXY_AGENT_REALIP_INCLUDE", "/etc/nginx/pickle-realip.conf"),
		CertbotBin:      env("PICKLE_PROXY_AGENT_CERTBOT_BIN", "certbot"),
		Webroot:         env("PICKLE_PROXY_AGENT_WEBROOT", "/var/www/certbot"),
		LEDir:           env("PICKLE_PROXY_AGENT_LE_DIR", "/etc/letsencrypt/live"),
		CertbotEmail:    env("PICKLE_PROXY_AGENT_CERTBOT_EMAIL", ""),
		RateLimitPerMin: 600,
		ExecTimeout:     60 * time.Second,
	}
	if strings.TrimSpace(c.Token) == "" {
		return Config{}, fmt.Errorf("PICKLE_PROXY_AGENT_TOKEN is required (empty token would leave the agent unauthenticated)")
	}
	return c, nil
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
