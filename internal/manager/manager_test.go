package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/fake"
	"github.com/pnuops/pickle-proxy-agent/internal/model"
	"github.com/pnuops/pickle-proxy-agent/internal/render"
	"github.com/pnuops/pickle-proxy-agent/internal/state"
)

type harness struct {
	mgr *Manager
	dir string
	ng  *fake.Nginx
	cb  *fake.Certbot
	st  *state.Store
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ng := &fake.Nginx{}
	cb := fake.NewCertbot()
	params := render.Params{HTTPSListen: "127.0.0.1:8443", WildcardCert: "/c/full.pem", WildcardKey: "/c/key.pem", Webroot: "/var/www/certbot"}
	mgr := New(dir, params, "/etc/letsencrypt/live", ng, cb, st)
	return &harness{mgr: mgr, dir: dir, ng: ng, cb: cb, st: st}
}

func (h *harness) confPath(fqdn string) string { return filepath.Join(h.dir, fqdn+".conf") }

func (h *harness) readConf(t *testing.T, fqdn string) string {
	t.Helper()
	b, err := os.ReadFile(h.confPath(fqdn))
	if err != nil {
		t.Fatalf("read %s: %v", fqdn, err)
	}
	return string(b)
}

func platformRoute(fqdn string, gen int64, ip string) model.Route {
	return model.Route{FQDN: fqdn, DesiredState: model.Present, Generation: gen, TargetIP: ip, TargetPort: 8080, CertRef: model.CertRefWildcard}
}

func TestApplyPresentRendersAndReloads(t *testing.T) {
	h := newHarness(t)
	code, res := h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 3, "172.29.4.11"))
	if code != 200 || !res.Applied || res.Generation != 3 {
		t.Fatalf("apply => %d %+v", code, res)
	}
	if !strings.Contains(h.readConf(t, "a.pickle.pnuops.com"), "proxy_pass http://172.29.4.11:8080;") {
		t.Fatal("vhost not rendered with target")
	}
	if _, reloads := h.ng.Counts(); reloads != 1 {
		t.Fatalf("reloads = %d, want 1", reloads)
	}
}

func TestApplyStaleRejected(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 5, "172.29.4.11")); code != 200 {
		t.Fatalf("first apply code %d", code)
	}
	// Equal generation is stale.
	code, res := h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 5, "172.29.4.99"))
	if code != 409 || res.Applied || res.Generation != 5 {
		t.Fatalf("equal-gen apply => %d %+v, want 409 applied=false gen=5", code, res)
	}
	// Lower generation is stale.
	code, res = h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 4, "172.29.4.99"))
	if code != 409 || res.Generation != 5 {
		t.Fatalf("lower-gen apply => %d %+v, want 409 gen=5", code, res)
	}
	// The stale apply must not have rewritten the live vhost.
	if !strings.Contains(h.readConf(t, "a.pickle.pnuops.com"), "172.29.4.11") {
		t.Fatal("stale apply clobbered the live target")
	}
	// A newer generation is accepted.
	if code, _ := h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 6, "172.29.4.22")); code != 200 {
		t.Fatalf("newer-gen apply code %d", code)
	}
}

func TestApplyAbsentRemovesButKeepsGeneration(t *testing.T) {
	h := newHarness(t)
	_, _ = h.mgr.Apply(context.Background(), platformRoute("gone.pickle.pnuops.com", 2, "172.29.4.11"))

	code, res := h.mgr.Apply(context.Background(), model.Route{FQDN: "gone.pickle.pnuops.com", DesiredState: model.Absent, Generation: 3})
	if code != 200 || !res.Applied {
		t.Fatalf("absent => %d %+v", code, res)
	}
	if _, err := os.Stat(h.confPath("gone.pickle.pnuops.com")); !os.IsNotExist(err) {
		t.Fatal("ABSENT should have removed the vhost file")
	}
	// A stale PRESENT (gen ≤ 3) must not resurrect the vhost onto a reused IP.
	code, _ = h.mgr.Apply(context.Background(), platformRoute("gone.pickle.pnuops.com", 3, "172.29.9.99"))
	if code != 409 {
		t.Fatalf("stale PRESENT after ABSENT => %d, want 409", code)
	}
	if _, err := os.Stat(h.confPath("gone.pickle.pnuops.com")); !os.IsNotExist(err) {
		t.Fatal("stale PRESENT resurrected a pruned vhost")
	}
}

func TestApplyNginxTestFailureLeavesLiveConfigUntouched(t *testing.T) {
	h := newHarness(t)
	// Establish a good live vhost at gen 1.
	_, _ = h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 1, "172.29.4.11"))
	_, reloadsBefore := h.ng.Counts()

	// gen 2 will fail nginx -t → must roll back to the gen-1 content, no reload.
	h.ng.FailTest = true
	h.ng.TestMsg = "nginx: [emerg] bad config"
	code, res := h.mgr.Apply(context.Background(), platformRoute("a.pickle.pnuops.com", 2, "172.29.4.222"))
	if code != 422 || res.Applied || !strings.Contains(res.Error, "emerg") {
		t.Fatalf("failed apply => %d %+v", code, res)
	}
	if got := h.readConf(t, "a.pickle.pnuops.com"); !strings.Contains(got, "172.29.4.11") || strings.Contains(got, "172.29.4.222") {
		t.Fatalf("live config not restored after nginx -t failure:\n%s", got)
	}
	if _, reloadsAfter := h.ng.Counts(); reloadsAfter != reloadsBefore {
		t.Fatalf("reload issued despite nginx -t failure: %d -> %d", reloadsBefore, reloadsAfter)
	}
	// The applied generation must still be 1 (the failed apply recorded nothing).
	if gen, _ := h.st.Generation("a.pickle.pnuops.com"); gen != 1 {
		t.Fatalf("generation advanced on failed apply: %d", gen)
	}
}

func TestApplyNewFqdnFailureRemovesTempFile(t *testing.T) {
	h := newHarness(t)
	h.ng.FailTest = true
	code, _ := h.mgr.Apply(context.Background(), platformRoute("new.pickle.pnuops.com", 1, "172.29.4.11"))
	if code != 422 {
		t.Fatalf("expected 422, got %d", code)
	}
	if _, err := os.Stat(h.confPath("new.pickle.pnuops.com")); !os.IsNotExist(err) {
		t.Fatal("failed first apply left a vhost file behind")
	}
}

func TestSyncAllPrunesStaleFiles(t *testing.T) {
	h := newHarness(t)
	_, _ = h.mgr.Apply(context.Background(), platformRoute("keep.pickle.pnuops.com", 1, "172.29.4.11"))
	_, _ = h.mgr.Apply(context.Background(), platformRoute("stale.pickle.pnuops.com", 1, "172.29.4.12"))

	req := model.SyncAllRequest{SnapshotGeneration: 50, Routes: []model.Route{
		platformRoute("keep.pickle.pnuops.com", 2, "172.29.4.11"),
		platformRoute("fresh.pickle.pnuops.com", 1, "172.29.4.13"),
	}}
	code, res := h.mgr.SyncAll(context.Background(), req)
	if code != 200 || !res.Applied {
		t.Fatalf("sync-all => %d %+v", code, res)
	}
	if _, err := os.Stat(h.confPath("stale.pickle.pnuops.com")); !os.IsNotExist(err) {
		t.Fatal("sync-all did not prune the stale vhost")
	}
	for _, f := range []string{"keep.pickle.pnuops.com", "fresh.pickle.pnuops.com"} {
		if _, err := os.Stat(h.confPath(f)); err != nil {
			t.Fatalf("sync-all dropped a manifest vhost %s: %v", f, err)
		}
	}
	if len(res.Pruned) != 1 || res.Pruned[0] != "stale.pickle.pnuops.com" {
		t.Fatalf("pruned = %v, want [stale...]", res.Pruned)
	}
	// The pruned FQDN must be gone from persisted state too.
	if _, known := h.st.Generation("stale.pickle.pnuops.com"); known {
		t.Fatal("pruned FQDN still in state after sync-all")
	}
}

func TestSyncAllStaleSnapshotRejected(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.mgr.SyncAll(context.Background(), model.SyncAllRequest{SnapshotGeneration: 10, Routes: nil}); code != 200 {
		t.Fatalf("first sync code %d", code)
	}
	code, res := h.mgr.SyncAll(context.Background(), model.SyncAllRequest{SnapshotGeneration: 10, Routes: nil})
	if code != 409 || res.SnapshotGeneration != 10 {
		t.Fatalf("stale snapshot => %d %+v, want 409 gen=10", code, res)
	}
}

func TestSyncAllFailureLeavesTreeUntouched(t *testing.T) {
	h := newHarness(t)
	_, _ = h.mgr.Apply(context.Background(), platformRoute("keep.pickle.pnuops.com", 1, "172.29.4.11"))

	h.ng.FailTest = true
	code, _ := h.mgr.SyncAll(context.Background(), model.SyncAllRequest{SnapshotGeneration: 20, Routes: []model.Route{
		platformRoute("other.pickle.pnuops.com", 1, "172.29.4.30"),
	}})
	if code != 422 {
		t.Fatalf("expected 422, got %d", code)
	}
	// The prior tree must be exactly restored: keep present, other absent.
	if _, err := os.Stat(h.confPath("keep.pickle.pnuops.com")); err != nil {
		t.Fatal("sync-all failure dropped the prior vhost")
	}
	if _, err := os.Stat(h.confPath("other.pickle.pnuops.com")); !os.IsNotExist(err) {
		t.Fatal("sync-all failure left a candidate vhost behind")
	}
	if h.st.SnapshotGeneration() != 0 {
		t.Fatal("snapshot generation advanced on failed sync-all")
	}
}

func TestApplyCustomDomainCertFailureSurfacedButVhostLive(t *testing.T) {
	h := newHarness(t)
	h.cb.EnsureErr = errors.New("DNS problem: NXDOMAIN looking up A for shop.example.com")
	r := model.Route{FQDN: "shop.example.com", DesiredState: model.Present, Generation: 1, TargetIP: "172.29.4.20", TargetPort: 3000, CertRef: "le-shop"}
	code, res := h.mgr.Apply(context.Background(), r)
	if code != 200 || !res.Applied {
		t.Fatalf("custom apply with cert failure => %d %+v (vhost should still be live)", code, res)
	}
	// Challenge vhost must be live (webroot reachable) even though issuance failed.
	if !strings.Contains(h.readConf(t, "shop.example.com"), "acme-challenge") {
		t.Fatal("challenge vhost not live after cert failure")
	}
	st := h.mgr.Status()
	var found bool
	for _, c := range st.Certs {
		if c.FQDN == "shop.example.com" {
			found = true
			if c.State != model.CertFailed || !strings.Contains(c.Error, "NXDOMAIN") {
				t.Fatalf("cert status = %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("cert failure not surfaced on /status")
	}
}

func TestApplyCustomDomainCertSuccessUpgradesToHTTPS(t *testing.T) {
	h := newHarness(t)
	r := model.Route{FQDN: "shop.example.com", DesiredState: model.Present, Generation: 1, TargetIP: "172.29.4.20", TargetPort: 3000, CertRef: "le-shop"}
	code, res := h.mgr.Apply(context.Background(), r)
	if code != 200 || !res.Applied {
		t.Fatalf("custom apply => %d %+v", code, res)
	}
	if len(h.cb.Ensured) != 1 || h.cb.Ensured[0] != "shop.example.com" {
		t.Fatalf("certbot Ensure not called: %v", h.cb.Ensured)
	}
	// After issuance the vhost must be upgraded to the full HTTPS form.
	conf := h.readConf(t, "shop.example.com")
	if !strings.Contains(conf, "listen 127.0.0.1:8443 ssl;") || !strings.Contains(conf, "return 301 https://") {
		t.Fatalf("vhost not upgraded to HTTPS after cert issuance:\n%s", conf)
	}
	st := h.mgr.Status()
	for _, c := range st.Certs {
		if c.FQDN == "shop.example.com" && c.State != model.CertOK {
			t.Fatalf("cert state = %s, want OK", c.State)
		}
	}
}
