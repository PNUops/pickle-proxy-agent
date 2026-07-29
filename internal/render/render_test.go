package render

import (
	"strings"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

func testParams() Params {
	return Params{
		HTTPSListen: "127.0.0.1:8443",
		WildcardCerts: map[string]CertPair{
			"pusan.dev": {
				Cert: "/etc/nginx/pickle-certs/pusan-dev.crt",
				Key:  "/etc/nginx/pickle-certs/pusan-dev.key",
			},
			"lab.example": {
				Cert: "/etc/nginx/pickle-certs/lab-example.crt",
				Key:  "/etc/nginx/pickle-certs/lab-example.key",
			},
		},
		Webroot: "/var/www/certbot",
	}
}

func TestRenderPlatform(t *testing.T) {
	r := model.Route{FQDN: "team-alpha-a1b2.pusan.dev", DesiredState: model.Present, Generation: 7, TargetIP: "172.29.4.11", TargetPort: 8080, CertRef: model.CertRefWildcardPrefix + "pusan.dev"}
	cert, key, err := CertPaths(r, testParams(), "/etc/letsencrypt/live")
	if err != nil {
		t.Fatal(err)
	}
	if cert != "/etc/nginx/pickle-certs/pusan-dev.crt" {
		t.Fatalf("wildcard cert path = %s", cert)
	}
	out, err := Render(r, testParams(), cert, key, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server_name team-alpha-a1b2.pusan.dev;",
		"listen 127.0.0.1:8443 ssl;",
		"ssl_certificate     /etc/nginx/pickle-certs/pusan-dev.crt;",
		"proxy_pass http://172.29.4.11:8080;",
		"proxy_set_header Connection $connection_upgrade;", // websocket upgrade
		"real_ip_header proxy_protocol;",
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
	cert, key, err := CertPaths(r, testParams(), "/etc/letsencrypt/live")
	if err != nil {
		t.Fatal(err)
	}
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

// The vhosts sit behind the TLS-terminating stream tier, whose PROXY header is the
// only carrier of the real client address: trusting a client-IP header from the
// loopback peer, or leaving $remote_addr as 127.0.0.1, both lose the true client.
func TestRenderRecoversClientIPFromProxyProtocol(t *testing.T) {
	p := testParams()
	for _, r := range []model.Route{
		{FQDN: "x.pusan.dev", DesiredState: model.Present, Generation: 1, TargetIP: "172.29.4.9", TargetPort: 80, CertRef: model.CertRefWildcardPrefix + "pusan.dev"},
		{FQDN: "shop.example.com", DesiredState: model.Present, Generation: 1, TargetIP: "172.29.4.9", TargetPort: 80, CertRef: "le"},
	} {
		out, err := Render(r, p, "/c.pem", "/k.pem", true)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"set_real_ip_from 127.0.0.1;", "real_ip_header proxy_protocol;", "X-Real-IP $pickle_client_ip;"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: vhost missing %q in:\n%s", r.FQDN, want, out)
			}
		}
		if strings.Contains(out, "real_ip_header CF-Connecting-IP") || strings.Contains(out, "pickle-realip") {
			t.Errorf("%s: vhost still trusts a header from the loopback peer:\n%s", r.FQDN, out)
		}
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
	if err := Validate(model.Route{FQDN: "gone.pusan.dev", DesiredState: model.Absent}); err != nil {
		t.Errorf("ABSENT with valid fqdn should pass: %v", err)
	}
}

// A route may only ever point at a user VM. Anything else — loopback, the bridge
// gateway, an internal service, a public address — must be refused before it can be
// rendered, so a hostile route cannot aim the reverse proxy at the internal networks.
func TestValidateRejectsTargetsOutsideTheVMNetwork(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "172.30.1.20", "172.28.255.255", "172.30.0.1", "8.8.8.8", "::1"} {
		r := model.Route{FQDN: "ok.pusan.dev", DesiredState: model.Present, TargetIP: ip, TargetPort: 80, CertRef: model.CertRefWildcardPrefix + "pusan.dev"}
		if err := Validate(r); err == nil {
			t.Errorf("targetIp %s is outside the user VM network but was accepted", ip)
		}
	}
	for _, ip := range []string{"172.29.0.1", "172.29.4.11", "172.29.255.254"} {
		r := model.Route{FQDN: "ok.pusan.dev", DesiredState: model.Present, TargetIP: ip, TargetPort: 80, CertRef: model.CertRefWildcardPrefix + "pusan.dev"}
		if err := Validate(r); err != nil {
			t.Errorf("targetIp %s is a user VM address but was rejected: %v", ip, err)
		}
	}
}

// A state the agent does not recognise must be refused, not waved through: the
// manager renders a vhost for anything that is not ABSENT, so a lowercase or empty
// state used to reach the renderer with the target checks skipped.
func TestValidateRejectsUnrecognisedDesiredStates(t *testing.T) {
	for _, state := range []string{"present", "Present", "", "PRESENT ", "garbage"} {
		r := model.Route{FQDN: "ok.pusan.dev", DesiredState: model.DesiredState(state),
			TargetIP: "172.30.1.20", TargetPort: 8080, CertRef: model.CertRefWildcardPrefix + "pusan.dev"}
		if err := Validate(r); err == nil {
			t.Errorf("desiredState %q reached the renderer with an internal target", state)
		}
	}
}

func TestValidateStillAcceptsAbsentWithoutATarget(t *testing.T) {
	r := model.Route{FQDN: "gone.pusan.dev", DesiredState: model.Absent}
	if err := Validate(r); err != nil {
		t.Fatalf("ABSENT route needs no target but was rejected: %v", err)
	}
}

func TestFileName(t *testing.T) {
	if got := FileName("a.b.com"); got != "a.b.com.conf" {
		t.Fatalf("FileName = %s", got)
	}
}

// An unconfigured root must fail rather than fall back. Rendering it against
// whichever pair happened to be configured would pass `nginx -t` and then serve a
// certificate that does not cover the name — a failure only the browser sees.
func TestCertPathsRefusesAnUnconfiguredRoot(t *testing.T) {
	r := model.Route{FQDN: "x.unknown.example", DesiredState: model.Present, Generation: 1,
		TargetIP: "172.29.4.11", TargetPort: 80,
		CertRef: model.CertRefWildcardPrefix + "unknown.example"}
	if _, _, err := CertPaths(r, testParams(), "/etc/letsencrypt/live"); err == nil {
		t.Fatal("expected an error for a root with no configured wildcard certificate")
	}
}

// Each root resolves to its own material, so adding a root is configuration only.
func TestCertPathsSelectsMaterialPerRoot(t *testing.T) {
	r := model.Route{FQDN: "team.lab.example", DesiredState: model.Present, Generation: 1,
		TargetIP: "172.29.4.11", TargetPort: 80,
		CertRef: model.CertRefWildcardPrefix + "lab.example"}
	cert, key, err := CertPaths(r, testParams(), "/etc/letsencrypt/live")
	if err != nil {
		t.Fatal(err)
	}
	if cert != "/etc/nginx/pickle-certs/lab-example.crt" || key != "/etc/nginx/pickle-certs/lab-example.key" {
		t.Fatalf("second root got %s / %s", cert, key)
	}
}
