package config

import "testing"

func TestHTTPProxyConfigurationRequiresDedicatedSocketAndExplicitPeers(t *testing.T) {
	for _, tc := range [][2]string{
		{"127.0.0.1:8080", ""}, {"", "127.0.0.1"}, {"0.0.0.0:8080", "127.0.0.1"},
		{"127.0.0.1:80", "127.0.0.1"}, {"localhost:8080", "127.0.0.1"},
		{"127.0.0.1:8080", "0.0.0.0/0"}, {"127.0.0.1:8080", "192.0.2.0/24"},
		{"127.0.0.1:8080", "127.0.0.1,127.0.0.1"}, {"127.0.0.1:8080", "127.0.0.1;return 200"},
	} {
		if _, _, err := parseHTTPProxy(tc[0], tc[1]); err == nil {
			t.Fatalf("accepted %v", tc)
		}
	}
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "test")
	t.Setenv("PICKLE_PROXY_AGENT_HTTP_PROXY_LISTEN", "127.0.0.1:8080")
	t.Setenv("PICKLE_PROXY_AGENT_HTTP_PROXY_TRUSTED_PEERS", "192.0.2.8,2001:db8::8")
	t.Setenv("PICKLE_PROXY_AGENT_TARGET_CIDR", "198.18.0.0/16")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPProxyListen != "127.0.0.1:8080" || len(cfg.HTTPProxyTrustedPeers) != 2 || cfg.TargetNetwork.String() != "198.18.0.0/16" {
		t.Fatalf("config = %+v", cfg)
	}
	t.Setenv("PICKLE_PROXY_AGENT_TARGET_CIDR", "198.18.0.1/16")
	if _, err := Load(); err == nil {
		t.Fatal("accepted target network host bits")
	}
}

func TestTargetNetworkAndHTTPProxyDefaultsPreserveLegacy(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TargetNetwork.String() != "172.29.0.0/16" || cfg.HTTPProxyListen != "" || len(cfg.HTTPProxyTrustedPeers) != 0 {
		t.Fatalf("defaults changed: %+v", cfg)
	}
}
