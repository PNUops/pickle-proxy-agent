package render

import (
	"strings"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

func TestSourcePolicyCoversEveryProxiedLocation(t *testing.T) {
	policy, err := sourcepolicy.Parse([]string{"192.0.2.0/24", "2001:db8::/32"})
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
			out, err := renderWithSourcePolicy(tc.route, testParams(), "/c.pem", "/k.pem", tc.ready, policy)
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
			if tc.ready && !strings.Contains(out, "real_ip_header proxy_protocol;") {
				t.Fatal("TLS source policy does not restore the trusted PROXY address")
			}
			if !tc.ready && strings.Contains(out, "real_ip_header") {
				t.Fatal("direct HTTP source policy must use its socket peer")
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
	deny, err := sourcepolicy.Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}
	denied, err := renderWithSourcePolicy(customRoute(), testParams(), "/c.pem", "/k.pem", false, deny)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(denied, "location / {\n        deny all;\n        proxy_pass") {
		t.Fatalf("empty policy did not deny proxy access:\n%s", denied)
	}
}
