package config

import "testing"

func TestLoadRequiresToken(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load must fail closed when the token is empty")
	}
}

func TestLoadRejectsPlaceholderToken(t *testing.T) {
	for _, tok := range []string{"CHANGEME", "CHANGME"} {
		t.Setenv("PICKLE_PROXY_AGENT_TOKEN", tok)
		if _, err := Load(); err == nil {
			t.Errorf("Load must reject the placeholder token %q", tok)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "tok")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.NginxDir != "/etc/nginx/pickle.d" {
		t.Errorf("NginxDir default = %s", c.NginxDir)
	}
	if len(c.AllowedSources) != 1 || c.AllowedSources[0] != "172.30.1.20" {
		t.Errorf("AllowedSources default = %v", c.AllowedSources)
	}
	if c.HTTPSListen != "127.0.0.1:8443" {
		t.Errorf("HTTPSListen default = %s", c.HTTPSListen)
	}
}

func TestAllowedSourcesParsing(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "tok")
	t.Setenv("PICKLE_PROXY_AGENT_ALLOWED_SRC", " 172.30.1.20 , 172.30.1.21 ,")
	c, _ := Load()
	if len(c.AllowedSources) != 2 {
		t.Fatalf("AllowedSources = %v", c.AllowedSources)
	}
}

func TestWildcardCertsParsing(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "tok")
	t.Setenv("PICKLE_PROXY_AGENT_WILDCARD_CERTS",
		" pusan.dev=/certs/a.crt:/certs/a.key , lab.example=/certs/b.crt:/certs/b.key ,")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.WildcardCerts) != 2 {
		t.Fatalf("WildcardCerts = %v", c.WildcardCerts)
	}
	if got := c.WildcardCerts["pusan.dev"]; got.Cert != "/certs/a.crt" || got.Key != "/certs/a.key" {
		t.Errorf("pusan.dev pair = %+v", got)
	}
	if got := c.WildcardCerts["lab.example"]; got.Cert != "/certs/b.crt" {
		t.Errorf("second root was dropped: %+v", c.WildcardCerts)
	}
}

// A typo that silently dropped a root would take its subdomains down at the next
// apply, long after the restart that caused it — so malformed entries are fatal.
func TestWildcardCertsRejectsMalformedEntries(t *testing.T) {
	for _, bad := range []string{
		"pusan.dev",                      // no pair
		"pusan.dev=/certs/only-cert.crt", // no key
		"=/certs/a.crt:/certs/a.key",     // no root
		"pusan.dev=:/certs/a.key",        // empty cert
		"pusan.dev=/certs/a.crt:",        // empty key
		"a.dev=/c:/k,a.dev=/c2:/k2",      // duplicate root
	} {
		t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "tok")
		t.Setenv("PICKLE_PROXY_AGENT_WILDCARD_CERTS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("Load accepted malformed wildcard config %q", bad)
		}
	}
}
