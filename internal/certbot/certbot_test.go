package certbot

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestCertbot returns a provider rooted at a temp config dir, along with helpers
// that materialise the two halves of a lineage independently.
func newTestCertbot(t *testing.T) *Certbot {
	t.Helper()
	root := t.TempDir()
	return New("/nonexistent/certbot", t.TempDir(), filepath.Join(root, "live"), "", time.Second)
}

func writeLiveCert(t *testing.T, c *Certbot, fqdn string) {
	t.Helper()
	dir := filepath.Join(c.LEDir, fqdn)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fullchain.pem", "privkey.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writeRenewalConf(t *testing.T, c *Certbot, fqdn string) {
	t.Helper()
	if err := os.MkdirAll(c.RenewalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.RenewalDir, fqdn+".conf"), []byte("# renewal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A removal can arrive for an FQDN that never had a certificate (or whose lineage was
// already dropped), so Delete must not shell out — the bin here would fail if it did.
func TestDeleteWithoutLineageIsNoOp(t *testing.T) {
	c := newTestCertbot(t)
	if err := c.Delete(context.Background(), "gone.example.com"); err != nil {
		t.Fatalf("delete without lineage: %v", err)
	}
}

// The renewal directory is certbot's own sibling of the live directory, so a test (or
// a deployment) that moves one moves the other. A trailing slash on the configured
// value must not nest the renewal directory inside the live one.
func TestRenewalDirIsSiblingOfLiveDir(t *testing.T) {
	for _, leDir := range []string{"/etc/letsencrypt/live", "/etc/letsencrypt/live/"} {
		c := New("certbot", "/var/www/certbot", leDir, "", time.Second)
		if c.RenewalDir != "/etc/letsencrypt/renewal" {
			t.Fatalf("LE dir %q: RenewalDir = %q, want /etc/letsencrypt/renewal", leDir, c.RenewalDir)
		}
	}
}

// The half-broken lineage this gate exists for: the cert files are gone but the
// renewal configuration remains, so `certbot renew` keeps trying and failing. It must
// be recognised as present so cleanup reclaims it.
func TestLineageExistsWithoutLiveCert(t *testing.T) {
	c := newTestCertbot(t)
	writeRenewalConf(t, c, "shop.example.com")

	if c.Exists("shop.example.com") {
		t.Fatal("Exists must stay false: no cert files for nginx to serve")
	}
	if !c.LineageExists("shop.example.com") {
		t.Fatal("a renewal configuration with no cert files is still a lineage")
	}
}

// The reverse leftover — cert files with no renewal configuration — is inert: renewal
// never looks at it and `certbot delete` cannot resolve it. Reporting it as a lineage
// would only turn cleanup into a guaranteed error.
func TestLiveCertWithoutRenewalConfIsNotALineage(t *testing.T) {
	c := newTestCertbot(t)
	writeLiveCert(t, c, "shop.example.com")

	if !c.Exists("shop.example.com") {
		t.Fatal("cert files are present")
	}
	if c.LineageExists("shop.example.com") {
		t.Fatal("cert files with no renewal configuration are not a deletable lineage")
	}
	// Nothing to reclaim, so Delete must not shell out (the bin here would fail).
	if err := c.Delete(context.Background(), "shop.example.com"); err != nil {
		t.Fatalf("delete of an unreclaimable leftover: %v", err)
	}
}

// A fully issued lineage — both halves on disk — is the ordinary case.
func TestLineageExistsForIssuedCert(t *testing.T) {
	c := newTestCertbot(t)
	writeLiveCert(t, c, "shop.example.com")
	writeRenewalConf(t, c, "shop.example.com")

	if !c.Exists("shop.example.com") || !c.LineageExists("shop.example.com") {
		t.Fatal("an issued cert is both usable and a lineage")
	}
}
