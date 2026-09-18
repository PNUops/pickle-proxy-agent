package nginx

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shortProofDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ng-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestVerifiedReloadRequiresFreshConfigurationReceipt(t *testing.T) {
	dir := shortProofDir(t)
	e, err := NewVerified(writeFakeNginx(t, filepath.Join(t.TempDir(), "reload")), time.Second, dir)
	if err != nil {
		t.Fatal(err)
	}
	e.ProofTimeout = 50 * time.Millisecond
	if err := e.Reload(context.Background()); err == nil {
		t.Fatal("reload without successful test accepted")
	}
	if _, err := e.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	uri, expected := e.proofURI, e.proofExpected
	listener, err := net.Listen("unix", e.proofSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == uri {
			_, _ = w.Write([]byte(expected))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	if err := e.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.proofExpected == expected {
		t.Fatal("configuration receipt was reused")
	}
	if err := e.Reload(context.Background()); err == nil {
		t.Fatal("old worker response confirmed a new configuration")
	}
}

func TestProofRefusesForeignReservedFile(t *testing.T) {
	dir := shortProofDir(t)
	path := filepath.Join(dir, ReloadProofConfig)
	if err := os.WriteFile(path, []byte("foreign config"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerified("nginx", time.Second, dir); err == nil {
		t.Fatal("foreign reserved file adopted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "foreign config" {
		t.Fatal("foreign config overwritten")
	}
}

func TestProofRefusesDirectoryWritableByOtherUsers(t *testing.T) {
	dir := shortProofDir(t)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerified("nginx", time.Second, dir); err == nil {
		t.Fatal("untrusted directory could forge local proof")
	}
}

func TestProofHasNoTCPListenerOrPublicHeader(t *testing.T) {
	dir := shortProofDir(t)
	e, err := NewVerified(writeFakeNginx(t, filepath.Join(t.TempDir(), "reload")), time.Second, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ReloadProofConfig))
	if strings.Count(string(data), "listen ") != 1 || !strings.Contains(string(data), "listen unix:") || strings.Contains(string(data), "add_header") {
		t.Fatalf("public proof surface: %s", data)
	}
}
