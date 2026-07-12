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
