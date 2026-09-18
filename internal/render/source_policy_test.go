package render

import (
	"strings"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

func TestSourcePolicyCoversEveryProxiedLocation(t *testing.T) {
	policy, err := sourcepolicy.FromCIDRs([]string{"192.0.2.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		route model.Route
		ready bool
	}{
		{"wildcard TLS", platformRoute(), true},
		{"custom TLS", customRoute(), true},
		{"custom HTTP fallback", customRoute(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.route.SourcePolicy = policy
			out, err := Render(tc.route, testParams(), "/c.pem", "/k.pem", tc.ready)
			if err != nil {
				t.Fatal(err)
			}
			want := "    location / {\n        allow 192.0.2.0/24;\n        allow 2001:db8::/32;\n        deny all;\n"
			if strings.Count(out, want) != 1 {
				t.Fatalf("proxied location is not protected exactly once:\n%s", out)
			}
			if strings.Index(out, want) > strings.Index(out, "proxy_pass http://") {
				t.Fatal("source policy appears after proxy_pass")
			}
			for _, forbidden := range []string{"real_ip_header X-Forwarded-For", "real_ip_header X-Real-IP", "$http_x_forwarded_for", "set_real_ip_from 0.0.0.0/0"} {
				if strings.Contains(out, forbidden) {
					t.Fatalf("source policy trusts caller input: %s", forbidden)
				}
			}
			if !strings.Contains(out, "proxy_set_header X-Forwarded-For $remote_addr;") || !strings.Contains(out, "proxy_set_header Forwarded \"\";") {
				t.Fatal("policy route retains an untrusted forwarding chain")
			}
			if tc.ready && !strings.Contains(out, "real_ip_header proxy_protocol;") {
				t.Fatal("TLS source policy does not restore the trusted PROXY address")
			}
			if !tc.ready && (!strings.Contains(out, "real_ip_header proxy_protocol;") || strings.Contains(out, "listen 80 proxy_protocol")) {
				t.Fatal("direct HTTP policy must ignore inherited HTTP address headers and keep its plain socket")
			}
			if start := strings.Index(out, "location /.well-known/acme-challenge/"); start >= 0 {
				challenge := out[start:]
				challenge = challenge[:strings.Index(challenge, "}")]
				if strings.Contains(challenge, "deny") || strings.Contains(challenge, "allow") {
					t.Fatalf("site policy blocks ACME challenges: %s", challenge)
				}
			}
		})
	}
}

func TestSourcePolicyDistinguishesLegacyFromExplicitDeny(t *testing.T) {
	legacy, err := Render(customRoute(), testParams(), "/c.pem", "/k.pem", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(legacy, "deny all;") || strings.Contains(legacy, "allow ") {
		t.Fatal("legacy route changed source access")
	}
	if !strings.Contains(legacy, "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;") || strings.Contains(legacy, "proxy_set_header Forwarded") {
		t.Fatal("field-absent legacy header shape changed")
	}
	deny, err := sourcepolicy.FromCIDRs([]string{})
	if err != nil {
		t.Fatal(err)
	}
	route := customRoute()
	route.SourcePolicy = deny
	denied, err := Render(route, testParams(), "/c.pem", "/k.pem", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(denied, "location / {\n        deny all;\n        proxy_pass") {
		t.Fatalf("empty policy did not deny proxy access:\n%s", denied)
	}
}
