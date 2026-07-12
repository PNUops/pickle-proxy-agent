// Package render turns a desired Route into the text of its nginx vhost file.
//
// Two shapes are produced, selected by certRef (docs/plan/06-domains-tls.md):
//
//   - platform subdomains (certRef == origin-wildcard): a single HTTPS server on
//     the internal 127.0.0.1:8443 tier using the Cloudflare Origin CA wildcard.
//   - custom domains (any other certRef): a per-domain Let's Encrypt cert. Because
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

// Params carries the deploy-time settings render needs that are not part of a Route.
type Params struct {
	HTTPSListen   string // 127.0.0.1:8443
	WildcardCert  string
	WildcardKey   string
	Webroot       string
	RealIPInclude string // "" to omit
}

// proxyCommon is the shared, websocket-upgrade-aware proxy block. `$connection_upgrade`
// comes from the `map $http_upgrade $connection_upgrade` defined once in the base
// nginx http{} context by the deploy (see scripts/nginx/pickle-base.conf).
const proxyCommon = `        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
`

type vhostData struct {
	FQDN          string
	Generation    int64
	Kind          string
	Target        string
	HTTPSListen   string
	CertPath      string
	KeyPath       string
	Webroot       string
	RealIPInclude string
	ProxyCommon   string
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

    real_ip_header CF-Connecting-IP;
{{- if .RealIPInclude}}
    include {{.RealIPInclude}};
{{- end}}

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

    real_ip_header CF-Connecting-IP;
{{- if .RealIPInclude}}
    include {{.RealIPInclude}};
{{- end}}

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
func IsPlatform(certRef string) bool { return certRef == model.CertRefWildcard }

// CertPaths resolves the certificate/key paths for a route given its certRef.
// For the wildcard it returns the configured Origin CA pair; for a custom domain
// it returns the Let's Encrypt live paths derived from the FQDN.
func CertPaths(r model.Route, p Params, leDir string) (cert, key string) {
	if IsPlatform(r.CertRef) {
		return p.WildcardCert, p.WildcardKey
	}
	base := strings.TrimRight(leDir, "/") + "/" + r.FQDN
	return base + "/fullchain.pem", base + "/privkey.pem"
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
		FQDN:          r.FQDN,
		Generation:    r.Generation,
		Target:        net.JoinHostPort(r.TargetIP, strconv.Itoa(r.TargetPort)),
		HTTPSListen:   p.HTTPSListen,
		CertPath:      certPath,
		KeyPath:       keyPath,
		Webroot:       p.Webroot,
		RealIPInclude: p.RealIPInclude,
		ProxyCommon:   proxyCommon,
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

// Validate checks a PRESENT route has a sane target. The API is the source of truth
// for the target IP (SSRF guard lives there); this is a defensive shape check so a
// malformed request never produces a config that only fails at `nginx -t`.
func Validate(r model.Route) error {
	if strings.TrimSpace(r.FQDN) == "" {
		return fmt.Errorf("fqdn is empty")
	}
	if !validFQDN(r.FQDN) {
		return fmt.Errorf("fqdn %q is not a valid hostname", r.FQDN)
	}
	if r.DesiredState != model.Present {
		return nil
	}
	if net.ParseIP(r.TargetIP) == nil {
		return fmt.Errorf("targetIp %q is not a valid IP", r.TargetIP)
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
