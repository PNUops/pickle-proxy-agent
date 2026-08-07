package certbot

import (
	"context"
	"testing"
	"time"
)

// A removal can arrive for an FQDN that never had a certificate (or whose lineage was
// already dropped), so Delete must not shell out — the bin here would fail if it did.
func TestDeleteWithoutLineageIsNoOp(t *testing.T) {
	c := New("/nonexistent/certbot", t.TempDir(), t.TempDir(), "", time.Second)
	if err := c.Delete(context.Background(), "gone.example.com"); err != nil {
		t.Fatalf("delete without lineage: %v", err)
	}
}
