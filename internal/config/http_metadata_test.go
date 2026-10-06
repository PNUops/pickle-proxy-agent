package config

import "testing"

func TestHTTPMetadataListenerRequiresExplicitDistinctSocketAndPeers(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "test-token")
	t.Setenv("PICKLE_PROXY_AGENT_HTTP_METADATA_LISTEN", "127.0.0.1:18080")
	t.Setenv("PICKLE_PROXY_AGENT_HTTP_METADATA_TRUSTED_PEERS", "192.0.2.10,127.0.0.1")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPMetadataListen != "127.0.0.1:18080" || len(c.HTTPMetadataTrustedPeers) != 2 {
		t.Fatalf("metadata configuration = %q %v", c.HTTPMetadataListen, c.HTTPMetadataTrustedPeers)
	}
	for _, tc := range []struct{ listen, peers string }{
		{"", "127.0.0.1"}, {"0.0.0.0:18080", "127.0.0.1"},
		{"127.0.0.1:80", "127.0.0.1"}, {"127.0.0.1:443", "127.0.0.1"},
		{"127.0.0.1:18080", ""}, {"127.0.0.1:18080", "127.0.0.1/32"},
		{"127.0.0.1:18080", "127.0.0.1,127.0.0.1"}, {"127.0.0.1:8443", "127.0.0.1"},
		{"172.30.1.10:9443", "127.0.0.1"},
	} {
		t.Setenv("PICKLE_PROXY_AGENT_HTTP_METADATA_LISTEN", tc.listen)
		t.Setenv("PICKLE_PROXY_AGENT_HTTP_METADATA_TRUSTED_PEERS", tc.peers)
		if _, err := Load(); err == nil {
			t.Errorf("accepted metadata listener/peers %q / %q", tc.listen, tc.peers)
		}
	}
}

func TestHTTPMetadataIsAbsentByDefault(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "test-token")
	t.Setenv("PICKLE_PROXY_AGENT_HTTP_METADATA_LISTEN", "")
	t.Setenv("PICKLE_PROXY_AGENT_HTTP_METADATA_TRUSTED_PEERS", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPMetadataListen != "" || len(c.HTTPMetadataTrustedPeers) != 0 {
		t.Fatalf("default metadata listener = %q %v", c.HTTPMetadataListen, c.HTTPMetadataTrustedPeers)
	}
}

func TestIngressMarkerRejectsRelativeAndNginxSyntaxPaths(t *testing.T) {
	t.Setenv("PICKLE_PROXY_AGENT_TOKEN", "test-token")
	for _, path := range []string{"relative", "/tmp/../marker", "/tmp/marker;", "/tmp/marker\n", "/tmp/$host", "/"} {
		t.Setenv("PICKLE_PROXY_AGENT_INGRESS_MARKER", path)
		if _, err := Load(); err == nil {
			t.Errorf("accepted marker %q", path)
		}
	}
	t.Setenv("PICKLE_PROXY_AGENT_INGRESS_MARKER", "/etc/nginx/public-site-enabled")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}
