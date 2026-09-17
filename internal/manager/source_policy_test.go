package manager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

func TestPolicyTestFailureRetainsPreviousConfigAndGeneration(t *testing.T) {
	h := newHarness(t)
	route := platformRoute("policy.pusan.dev", 1, "172.29.4.11")
	if code, _ := h.mgr.Apply(context.Background(), route); code != 200 {
		t.Fatal(code)
	}
	before := h.readConf(t, route.FQDN)
	route.Generation = 2
	route.SourcePolicy, _ = sourcepolicy.FromCIDRs([]string{})
	h.ng.FailTest = true
	if code, result := h.mgr.Apply(context.Background(), route); code != 422 || result.Applied {
		t.Fatalf("failed test = %d/%+v", code, result)
	}
	if h.readConf(t, route.FQDN) != before {
		t.Fatal("nginx validation failure changed config")
	}
	if generation, _ := h.st.Generation(route.FQDN); generation != 1 {
		t.Fatal("generation advanced without apply")
	}
	if _, reloads := h.ng.Counts(); reloads != 1 {
		t.Fatal("invalid policy candidate was reloaded")
	}
}

func TestConfiguredTargetNetworkReachesManagerValidation(t *testing.T) {
	h := newHarness(t)
	h.mgr.params.TargetNetwork = netip.MustParsePrefix("198.18.0.0/16")
	if code, _ := h.mgr.Apply(context.Background(), platformRoute("new.pusan.dev", 1, "198.18.1.2")); code != 200 {
		t.Fatalf("new network rejected: %d", code)
	}
	if code, _ := h.mgr.Apply(context.Background(), platformRoute("old.pusan.dev", 1, "172.29.1.2")); code != 422 {
		t.Fatalf("old network accepted: %d", code)
	}
}
