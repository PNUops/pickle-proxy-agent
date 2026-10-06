package render

import (
	"net/netip"
	"strings"
	"testing"
)

func TestMetadataVhostIsAvailableForEveryRoutePhaseWithoutBackendProxy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform bool
		ready    bool
	}{
		{"platform", true, true}, {"custom pending certificate", false, false}, {"custom ready", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testParams()
			p.HTTPMetadataListen = "127.0.0.1:18080"
			p.HTTPMetadataTrustedPeers = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
			r := customRoute()
			if tc.platform {
				r = platformRoute()
			}
			text, err := Render(r, p, "/cert.pem", "/key.pem", tc.ready)
			if err != nil {
				t.Fatal(err)
			}
			start := strings.Index(text, "server {\n    listen 127.0.0.1:18080;")
			if start < 0 {
				t.Fatalf("metadata vhost missing in %s", text)
			}
			end := strings.Index(text[start:], "\nserver {")
			if end < 0 {
				t.Fatalf("metadata vhost missing in %s", text)
			}
			metadata := text[start : start+end]
			for _, expected := range []string{
				`if ($realip_remote_addr !~ "^(192\.0\.2\.10)$") { return 403; }`,
				"location = /__pickle_vm_host", "if ($request_method != HEAD) { return 405; }",
				"return 204;", "if ($args != \"\") { return 404; }", "try_files $uri =404;",
			} {
				if !strings.Contains(metadata, expected) {
					t.Errorf("metadata missing %q", expected)
				}
			}
			if strings.Contains(metadata, "proxy_pass") || strings.Contains(metadata, "allow ") || strings.Contains(metadata, "real_ip_header") {
				t.Fatalf("metadata contains a backend/client-policy or header-trust path: %s", metadata)
			}
		})
	}
}

func TestHTTPSRouteRequiresExactSNIAndRawHost(t *testing.T) {
	for _, r := range []struct{ platform bool }{{true}, {false}} {
		route := customRoute()
		if r.platform {
			route = platformRoute()
		}
		text, err := Render(route, testParams(), "/cert.pem", "/key.pem", true)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, `if ($ssl_server_name !~* "^`) || !strings.Contains(text, `(:443)?$") { return 421; }`) {
			t.Fatalf("HTTPS route has no exact authority gate: %s", text)
		}
		if !strings.Contains(text, strings.ReplaceAll(route.FQDN, ".", `\.`)) {
			t.Fatalf("FQDN regex dots are not escaped: %s", text)
		}
	}
}

func TestMetadataParamsRejectConfigBypassAndLeaveDefaultAbsent(t *testing.T) {
	p := testParams()
	text, err := Render(platformRoute(), p, "/cert.pem", "/key.pem", true)
	if err != nil || strings.Contains(text, "/__pickle_vm_host") {
		t.Fatalf("default metadata changed: %v %s", err, text)
	}
	p.HTTPMetadataListen = "0.0.0.0:18080"
	p.HTTPMetadataTrustedPeers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if _, err := Render(platformRoute(), p, "/cert.pem", "/key.pem", true); err == nil {
		t.Fatal("renderer accepted wildcard metadata socket")
	}
	p.HTTPMetadataListen = "127.0.0.1:18080"
	p.HTTPMetadataTrustedPeers = append(p.HTTPMetadataTrustedPeers, p.HTTPMetadataTrustedPeers[0])
	if _, err := Render(platformRoute(), p, "/cert.pem", "/key.pem", true); err == nil {
		t.Fatal("renderer accepted duplicate trusted peers")
	}
}

func TestIngressMarkerClosesBackendWithoutClosingMetadataAndAcme(t *testing.T) {
	p := testParams()
	p.IngressMarker = "/etc/nginx/public-site-enabled"
	p.HTTPMetadataListen = "127.0.0.1:18080"
	p.HTTPMetadataTrustedPeers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	for _, ready := range []bool{false, true} {
		text, err := Render(customRoute(), p, "/cert.pem", "/key.pem", ready)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "if (!-f /etc/nginx/public-site-enabled) { return 503; }") {
			t.Fatalf("backend marker missing in %s", text)
		}
		first := text[:strings.Index(text, "\nserver {\n    listen 80;")]
		if strings.Contains(first, "public-site-enabled") {
			t.Fatalf("metadata/ACME was gated by the backend marker: %s", first)
		}
	}
}
