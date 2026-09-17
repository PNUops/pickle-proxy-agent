package render

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

func TestSourcePolicyNginxReloadPreservesActiveResponse(t *testing.T) {
	binary := os.Getenv("PICKLE_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("set PICKLE_TEST_NGINX_BIN in an isolated nginx test environment")
	}
	finish := make(chan struct{})
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Accel-Buffering", "no")
		_, _ = io.WriteString(w, "started\n")
		w.(http.Flusher).Flush()
		select {
		case <-finish:
			_, _ = io.WriteString(w, "finished\n")
		case <-r.Context().Done():
		}
	}))
	defer backend.Close()
	dir := t.TempDir()
	address := unusedTestAddress(t)
	params := testParams()
	params.Webroot = dir
	params.SiteLimits = false
	route := customRoute()
	confPath := filepath.Join(dir, "nginx.conf")
	writeConfig := func(cidrs []string) {
		t.Helper()
		policy, err := sourcepolicy.FromCIDRs(cidrs)
		if err != nil {
			t.Fatal(err)
		}
		route.SourcePolicy = policy
		vhost, err := Render(route, params, "", "", false)
		if err != nil {
			t.Fatal(err)
		}
		vhost = strings.ReplaceAll(vhost, "listen 80;", "listen "+address+";")
		vhost = strings.ReplaceAll(vhost, fmt.Sprintf("proxy_pass http://%s:%d;", route.TargetIP, route.TargetPort), "proxy_pass "+backend.URL+";")
		config := "daemon off;\nworker_processes 1;\npid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp { access_log off; map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n" + vhost + "}\n"
		if err := os.WriteFile(confPath, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig([]string{"127.0.0.1/32"})
	startTestNginx(t, binary, confPath, dir, address)
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("http://" + address + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "started\n" {
		t.Fatalf("active response: %q/%v", first, err)
	}
	writeConfig([]string{})
	for _, args := range [][]string{{"-t"}, {"-s", "reload"}} {
		output, err := exec.Command(binary, append([]string{"-p", dir + "/", "-c", confPath}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("nginx %v: %v\n%s", args, err, output)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	denied := false
	for time.Now().Before(deadline) {
		current, err := client.Get("http://" + address + "/")
		if err != nil {
			t.Fatal(err)
		}
		current.Body.Close()
		if current.StatusCode == http.StatusForbidden {
			denied = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !denied {
		t.Fatal("new connections did not receive the new deny policy")
	}
	close(finish)
	remaining, err := io.ReadAll(reader)
	if err != nil || string(remaining) != "finished\n" {
		t.Fatalf("reload interrupted active response: %q/%v", remaining, err)
	}
}
