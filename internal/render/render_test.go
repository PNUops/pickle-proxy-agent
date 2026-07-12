package render

import (
	"strings"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

func testParams() Params {
	return Params{
		HTTPSListen:   "127.0.0.1:8443",
		WildcardCert:  "/etc/nginx/certs/origin/fullchain.pem",
		WildcardKey:   "/etc/nginx/certs/origin/privkey.pem",
		Webroot:       "/var/www/certbot",
		RealIPInclude: "/etc/nginx/pickle-realip.conf",
	}
}

func TestRenderPlatform(t *testing.T) {
	r := model.Route{FQDN: "team-alpha-a1b2.pickle.pnuops.com", DesiredState: model.Present, Generation: 7, TargetIP: "172.29.4.11", TargetPort: 8080, CertRef: model.CertRefWildcard}
	cert, key := CertPaths(r, testParams(), "/etc/letsencrypt/live")
	if cert != "/etc/nginx/certs/origin/fullchain.pem" {
		t.Fatalf("wildcard cert path = %s", cert)
	}
	out, err := Render(r, testParams(), cert, key, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server_name team-alpha-a1b2.pickle.pnuops.com;",
		"listen 127.0.0.1:8443 ssl;",
		"ssl_certificate     /etc/nginx/certs/origin/fullchain.pem;",
		"proxy_pass http://172.29.4.11:8080;",
		"proxy_set_header Connection $connection_upgrade;", // websocket upgrade
		"include /etc/nginx/pickle-realip.conf;",
		"kind=platform",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("platform vhost missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "listen 80;") {
		t.Errorf("platform vhost should not have a :80 server")
	}
}

func TestRenderCustomChallengeThenHTTPS(t *testing.T) {
	r := model.Route{FQDN: "shop.example.com", DesiredState: model.Present, Generation: 1, TargetIP: "172.29.4.20", TargetPort: 3000, CertRef: "le-shop"}
	cert, key := CertPaths(r, testParams(), "/etc/letsencrypt/live")
	if cert != "/etc/letsencrypt/live/shop.example.com/fullchain.pem" {
		t.Fatalf("LE cert path = %s", cert)
	}

	// certReady=false → challenge-only vhost: :80 with acme-challenge, no ssl server.
	challenge, err := Render(r, testParams(), cert, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(challenge, "location /.well-known/acme-challenge/") {
		t.Errorf("challenge vhost missing acme-challenge location:\n%s", challenge)
	}
	if strings.Contains(challenge, "ssl_certificate") {
		t.Errorf("challenge vhost must not reference a (not-yet-issued) cert:\n%s", challenge)
	}

	// certReady=true → full HTTPS vhost with :80 redirect + :8443 ssl.
	full, err := Render(r, testParams(), cert, key, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"return 301 https://$host$request_uri;",
		"listen 127.0.0.1:8443 ssl;",
		"ssl_certificate     /etc/letsencrypt/live/shop.example.com/fullchain.pem;",
		"location /.well-known/acme-challenge/",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("custom HTTPS vhost missing %q in:\n%s", want, full)
		}
	}
}

func TestRenderOmitsRealIPIncludeWhenUnset(t *testing.T) {
	p := testParams()
	p.RealIPInclude = ""
	r := model.Route{FQDN: "x.pickle.pnuops.com", DesiredState: model.Present, Generation: 1, TargetIP: "172.29.4.9", TargetPort: 80, CertRef: model.CertRefWildcard}
	out, _ := Render(r, p, p.WildcardCert, p.WildcardKey, true)
	if strings.Contains(out, "include ;") || strings.Contains(out, "pickle-realip") {
		t.Errorf("empty RealIPInclude should emit no include line:\n%s", out)
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := []model.Route{
		{FQDN: "", DesiredState: model.Present, TargetIP: "1.2.3.4", TargetPort: 80},
		{FQDN: "bad host.com", DesiredState: model.Present, TargetIP: "1.2.3.4", TargetPort: 80},
		{FQDN: "evil.com/../etc", DesiredState: model.Present, TargetIP: "1.2.3.4", TargetPort: 80},
		{FQDN: "ok.com", DesiredState: model.Present, TargetIP: "not-an-ip", TargetPort: 80},
		{FQDN: "ok.com", DesiredState: model.Present, TargetIP: "1.2.3.4", TargetPort: 0},
		{FQDN: "ok.com", DesiredState: model.Present, TargetIP: "1.2.3.4", TargetPort: 70000},
	}
	for i, c := range cases {
		if err := Validate(c); err == nil {
			t.Errorf("case %d: expected validation error for %+v", i, c)
		}
	}
	// ABSENT needs only a valid FQDN, no target.
	if err := Validate(model.Route{FQDN: "gone.pickle.pnuops.com", DesiredState: model.Absent}); err != nil {
		t.Errorf("ABSENT with valid fqdn should pass: %v", err)
	}
}

func TestFileName(t *testing.T) {
	if got := FileName("a.b.com"); got != "a.b.com.conf" {
		t.Fatalf("FileName = %s", got)
	}
}
