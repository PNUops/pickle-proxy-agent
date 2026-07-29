// Package render turns a desired Route into the text of its nginx vhost file.
//
// Two shapes are produced, selected by certRef:
//
//   - platform subdomains (certRef "wildcard:<root>"): a single HTTPS server on
//     the internal 127.0.0.1:8443 tier using the Cloudflare Origin CA wildcard
//     configured for that root domain.
//   - custom domains (certRef equal to the configured Let's Encrypt ref): a
//     per-domain Let's Encrypt cert. Because
//     the LE cert does not exist until certbot runs, rendering is two-phase — a
//     challenge-only :80 vhost (webroot reachable, site proxied over HTTP) until
//     the cert lands, then the full :80-redirect + :8443-HTTPS vhost.
//
// The websocket-aware proxy directives are a single shared snippet (proxyCommon)
// inlined into every location so each FQDN remains exactly one self-contained file
// — nothing outside /etc/nginx/pickle.d/<fqdn>.conf is written.
package render

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"text/template"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

// CertPair is one certificate/key pair on disk.
type CertPair struct {
	Cert string
	Key  string
}

// Params carries the deploy-time settings render needs that are not part of a Route.
type Params struct {
	HTTPSListen string // 127.0.0.1:8443
	// LECertRef is the one certRef that means "per-domain Let's Encrypt". It is
	// matched exactly rather than treated as a catch-all: a ref this agent does
	// not recognise is far more likely to come from a pickle-api on the other
	// side of a contract change than to be a custom domain, and treating it as
	// one would drive a public certificate issuance for a platform subdomain.
	LECertRef string
	// WildcardCerts is the certificate material per platform root domain. A route
	// naming a root that is absent here is refused: rendering it with whatever
	// other pair happened to be configured would serve a certificate that does
	// not cover the name, which fails in the browser rather than here.
	WildcardCerts map[string]CertPair
	Webroot       string
}

// proxyCommon is the shared, websocket-upgrade-aware proxy block. `$connection_upgrade`
// comes from the `map $http_upgrade $connection_upgrade` defined once in the base
// nginx http{} context by the deploy (see scripts/nginx/pickle-base.conf), and
// `$pickle_client_ip` from the operator-managed client-IP validation map described
// in the same file: it is the peer address, except when the peer is a known CDN
// edge, where the edge's client-IP header is trusted instead.
const proxyCommon = `        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $pickle_client_ip;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
`

type vhostData struct {
	FQDN        string
	Generation  int64
	Kind        string
	Target      string
	HTTPSListen string
	CertPath    string
	KeyPath     string
	Webroot     string
	ProxyCommon string
}

var platformTmpl = template.Must(template.New("platform").Parse(
	`# Managed by pickle-proxy-agent — do not edit by hand.
# fqdn={{.FQDN}} generation={{.Generation}} kind={{.Kind}}
server {
    listen {{.HTTPSListen}} ssl;
    http2 on;
    server_name {{.FQDN}};

    ssl_certificate     {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};

    # This socket's only peer is the TLS-terminating stream tier, which prepends a
    # PROXY header carrying the true public peer; restore it into $remote_addr.
    # $pickle_client_ip then decides whether a CF-Connecting-IP header from that
    # peer may be believed (both come from the base http{} wiring).
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    location / {
        proxy_pass http://{{.Target}};
{{.ProxyCommon}}    }
}
`))

var customHTTPSTmpl = template.Must(template.New("customHTTPS").Parse(
	`# Managed by pickle-proxy-agent — do not edit by hand.
# fqdn={{.FQDN}} generation={{.Generation}} kind={{.Kind}}
server {
    listen 80;
    server_name {{.FQDN}};

    location /.well-known/acme-challenge/ {
        root {{.Webroot}};
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
server {
    listen {{.HTTPSListen}} ssl;
    http2 on;
    server_name {{.FQDN}};

    ssl_certificate     {{.CertPath}};
    ssl_certificate_key {{.KeyPath}};

    # This socket's only peer is the TLS-terminating stream tier, which prepends a
    # PROXY header carrying the true public peer; restore it into $remote_addr.
    # $pickle_client_ip then decides whether a CF-Connecting-IP header from that
    # peer may be believed (both come from the base http{} wiring).
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    location / {
        proxy_pass http://{{.Target}};
{{.ProxyCommon}}    }
}
`))

var customChallengeTmpl = template.Must(template.New("customChallenge").Parse(
	`# Managed by pickle-proxy-agent — do not edit by hand.
# fqdn={{.FQDN}} generation={{.Generation}} kind={{.Kind}} (cert pending)
server {
    listen 80;
    server_name {{.FQDN}};

    location /.well-known/acme-challenge/ {
        root {{.Webroot}};
    }
    location / {
        proxy_pass http://{{.Target}};
{{.ProxyCommon}}    }
}
`))

// FileName is the on-disk name for an FQDN's vhost, relative to the include dir.
func FileName(fqdn string) string { return fqdn + ".conf" }

// IsPlatform reports whether a certRef selects the platform wildcard template.
func IsPlatform(certRef string) bool {
	_, ok := model.WildcardRoot(certRef)
	return ok
}

// CertPaths resolves the certificate/key paths for a route given its certRef.
// For a wildcard ref it returns the pair configured for that root; for a custom
// domain the Let's Encrypt live paths derived from the FQDN.
//
// Neither branch has a fallback. An unconfigured root is an error because the
// agent is the only place that knows which certificate covers which root, and a
// ref that matches neither shape is an error because the alternative — treating
// it as a custom domain, as this used to — turns a version skew between the two
// sides into a public certificate issued for a platform subdomain. Both produce a
// config `nginx -t` would happily accept.
func CertPaths(r model.Route, p Params, leDir string) (cert, key string, err error) {
	if root, ok := model.WildcardRoot(r.CertRef); ok {
		pair, configured := p.WildcardCerts[root]
		if !configured {
			return "", "", fmt.Errorf("no wildcard certificate configured for root domain %q", root)
		}
		return pair.Cert, pair.Key, nil
	}
	if r.CertRef != p.LECertRef {
		return "", "", fmt.Errorf("unrecognised certRef %q (expected %s<root> or %q) — "+
			"refusing rather than treating it as a custom domain",
			r.CertRef, model.CertRefWildcardPrefix, p.LECertRef)
	}
	base := strings.TrimRight(leDir, "/") + "/" + r.FQDN
	return base + "/fullchain.pem", base + "/privkey.pem", nil
}

// Render produces the vhost file content for a PRESENT route.
//
// certReady must reflect whether the LE cert already exists on disk for a custom
// domain; when false a custom domain renders the challenge-only vhost so certbot
// can complete HTTP-01 before the HTTPS server (which would fail `nginx -t` on a
// missing cert) is introduced. It is ignored for platform routes.
func Render(r model.Route, p Params, certPath, keyPath string, certReady bool) (string, error) {
	if err := Validate(r); err != nil {
		return "", err
	}
	d := vhostData{
		FQDN:        r.FQDN,
		Generation:  r.Generation,
		Target:      net.JoinHostPort(r.TargetIP, strconv.Itoa(r.TargetPort)),
		HTTPSListen: p.HTTPSListen,
		CertPath:    certPath,
		KeyPath:     keyPath,
		Webroot:     p.Webroot,
		ProxyCommon: proxyCommon,
	}
	var tmpl *template.Template
	switch {
	case IsPlatform(r.CertRef):
		d.Kind = "platform"
		tmpl = platformTmpl
	case certReady:
		d.Kind = "custom"
		tmpl = customHTTPSTmpl
	default:
		d.Kind = "custom"
		tmpl = customChallengeTmpl
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// targetNet is the user-VM network. Every proxy target must live inside it: the
// only thing a route may point at is a user's VM. Keeping the check here means a
// route that somehow asks for a loopback, link-local, gateway or internal-service
// address is refused before it is ever written to disk, so a compromised caller
// (or a stolen agent token) cannot turn the reverse proxy into a probe of the
// internal networks. Defence in depth: the API validates the target too.
var targetNet = func() *net.IPNet {
	_, n, err := net.ParseCIDR("172.29.0.0/16")
	if err != nil {
		panic(err)
	}
	return n
}()

// Validate checks a route has a sane target: a well-formed FQDN, a port in range,
// and an IP inside the user-VM network. The API is the first line of defence for
// the target IP; this is the agent's own guard, so a malformed or hostile request
// never produces a config that only fails at `nginx -t` — or worse, one that passes.
//
// The state check is deliberately "anything that is not ABSENT gets the target
// rules", mirroring the manager, which renders a vhost for every state it does not
// recognise as ABSENT. Gating on "== PRESENT" instead would let an unrecognised
// state (a lowercase spelling, an empty string) render a vhost with the target
// checks skipped entirely. Unknown states are refused outright so the two layers
// cannot drift apart again.
func Validate(r model.Route) error {
	if strings.TrimSpace(r.FQDN) == "" {
		return fmt.Errorf("fqdn is empty")
	}
	if !validFQDN(r.FQDN) {
		return fmt.Errorf("fqdn %q is not a valid hostname", r.FQDN)
	}
	switch r.DesiredState {
	case model.Absent:
		return nil
	case model.Present:
	default:
		return fmt.Errorf("desiredState %q is not recognised", r.DesiredState)
	}
	ip := net.ParseIP(r.TargetIP)
	if ip == nil {
		return fmt.Errorf("targetIp %q is not a valid IP", r.TargetIP)
	}
	if !targetNet.Contains(ip) {
		return fmt.Errorf("targetIp %q is outside the user VM network %s", r.TargetIP, targetNet)
	}
	if r.TargetPort < 1 || r.TargetPort > 65535 {
		return fmt.Errorf("targetPort %d out of range", r.TargetPort)
	}
	return nil
}

// validFQDN accepts RFC-1123 dotted hostnames; rejects anything that could break
// out of the server_name / file path (slashes, spaces, config metacharacters).
func validFQDN(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i, c := range label {
			switch {
			case c >= 'a' && c <= 'z':
			case c >= 'A' && c <= 'Z':
			case c >= '0' && c <= '9':
			case c == '-' && i != 0 && i != len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}
