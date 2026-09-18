package render

import "testing"

func TestParseTargetNetworkAcceptsConfiguredGuestNetworks(t *testing.T) {
	for _, value := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		prefix, err := ParseTargetNetwork(value)
		if err != nil || prefix.String() != value {
			t.Fatalf("target network %q = %v, %v", value, prefix, err)
		}
	}
}

func TestParseTargetNetworkRejectsAmbiguousOrUnsupportedNetworks(t *testing.T) {
	for _, value := range []string{"", "192.0.2.7/24", "192.0.2.0", "example.com/24", "::/0", "::ffff:192.0.2.0/120", "192.0.2.0/024", "192.0.2.0/24\n"} {
		if prefix, err := ParseTargetNetwork(value); err == nil || prefix.IsValid() {
			t.Fatalf("invalid target network %q accepted: %v, %v", value, prefix, err)
		}
	}
}
