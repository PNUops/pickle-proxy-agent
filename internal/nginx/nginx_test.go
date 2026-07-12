package nginx

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// writeFakeNginx drops a shell script that mimics nginx's CLI: `-t` exits non-zero
// (printing to stderr) when FAIL_NGINX_T is set; `-s reload` records a marker file.
// This exercises Exec's real os/exec path without a real nginx.
func writeFakeNginx(t *testing.T, marker string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake nginx script is POSIX shell")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nginx")
	script := `#!/bin/sh
case "$1" in
  -t)
    if [ -n "$FAIL_NGINX_T" ]; then
      echo "nginx: [emerg] simulated bad config" 1>&2
      exit 1
    fi
    echo "nginx: configuration file test is successful"
    ;;
  -s)
    echo reloaded > "` + marker + `"
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExecTestAndReload(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "reloaded")
	e := New(writeFakeNginx(t, marker), 5*time.Second)

	out, err := e.Test(context.Background())
	if err != nil {
		t.Fatalf("Test errored on good config: %v (%s)", err, out)
	}
	if err := e.Reload(context.Background()); err != nil {
		t.Fatalf("Reload errored: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("reload did not run the binary: %v", err)
	}
}

func TestExecTestFailureSurfacesStderr(t *testing.T) {
	e := New(writeFakeNginx(t, filepath.Join(t.TempDir(), "m")), 5*time.Second)
	t.Setenv("FAIL_NGINX_T", "1")
	out, err := e.Test(context.Background())
	if err == nil {
		t.Fatal("expected Test to fail")
	}
	if out == "" || !contains(out, "simulated bad config") {
		t.Fatalf("stderr not captured: %q", out)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
