package manager

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pnuops/pickle-proxy-agent/internal/fake"
	"github.com/pnuops/pickle-proxy-agent/internal/model"
	"github.com/pnuops/pickle-proxy-agent/internal/nginx"
	"github.com/pnuops/pickle-proxy-agent/internal/render"
	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
	"github.com/pnuops/pickle-proxy-agent/internal/state"
)

func TestReloadProofRejectsOccupiedSocketRestoresAndRetriesSameGeneration(t *testing.T) {
	binary := os.Getenv("PICKLE_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("requires an isolated nginx test environment with port 80 available")
	}
	dir, err := os.MkdirTemp("/tmp", "proxy-proof-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sites := filepath.Join(dir, "sites")
	if err := os.Mkdir(sites, 0750); err != nil {
		t.Fatal(err)
	}
	ready, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	readyAddress := ready.Addr().String()
	ready.Close()
	conf := filepath.Join(dir, "nginx.conf")
	configuration := "daemon off; worker_processes 1; pid " + filepath.Join(dir, "nginx.pid") + "; error_log stderr; events {} http { access_log off; map $http_upgrade $connection_upgrade { default upgrade; '' close; } server { listen " + readyAddress + "; return 204; } include " + sites + "/*.conf; }"
	if err := os.WriteFile(conf, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "nginx.log"))
	if err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "-p", dir+"/", "-c", conf)
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Signal(syscall.SIGQUIT)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = process.Process.Kill()
			<-done
		}
		logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logFile.Name())
			t.Logf("nginx: %s", data)
		}
	})
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 10 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get("http://" + readyAddress)
		if err == nil {
			response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nginx startup timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	finish := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			_, _ = io.WriteString(w, "site")
			return
		}
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
	defer func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	}()
	upstream, _ := url.Parse(backend.URL)
	host, portText, _ := net.SplitHostPort(upstream.Host)
	port, _ := strconv.Atoi(portText)
	engine, err := nginx.NewVerified(binary, 10*time.Second, sites)
	if err != nil {
		t.Fatal(err)
	}
	engine.PrefixArgs = []string{"-p", dir + "/", "-c", conf}
	engine.ProofTimeout = 4 * time.Second
	store, err := state.Load(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	certbot := fake.NewCertbot()
	certbot.EnsureErr = errors.New("certificate issuance disabled in isolated test")
	mgr := New(sites, render.Params{TargetNetwork: netip.MustParsePrefix("127.0.0.0/8"), LECertRef: "letsencrypt", Webroot: dir}, dir, engine, certbot, store)
	policy, _ := sourcepolicy.FromCIDRs([]string{"127.0.0.1/32"})
	route := model.Route{FQDN: "policy.example", DesiredState: model.Present, Generation: 1, TargetIP: host, TargetPort: port, CertRef: "letsencrypt", SourcePolicy: policy}
	if code, result := mgr.Apply(context.Background(), route); code != 200 || !result.Applied {
		t.Fatalf("initial apply %d/%+v", code, result)
	}
	before, _ := os.ReadFile(filepath.Join(sites, route.FQDN+".conf"))
	request := func(path string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = route.FQDN
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	stream := request("/stream")
	defer stream.Body.Close()
	reader := bufio.NewReader(stream.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "started\n" {
		t.Fatalf("active response %q/%v", line, err)
	}
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	mgr.params.HTTPProxyListen = occupied.Addr().String()
	mgr.params.HTTPProxyTrustedPeers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	route.Generation = 2
	route.SourcePolicy, _ = sourcepolicy.FromCIDRs([]string{})
	if code, result := mgr.Apply(context.Background(), route); code != 422 || result.Applied || !strings.Contains(result.Error, "configuration proof") {
		t.Fatalf("occupied port falsely applied: %d/%+v", code, result)
	}
	if generation, _ := store.Generation(route.FQDN); generation != 1 {
		t.Fatalf("failed reload advanced generation: %d", generation)
	}
	after, _ := os.ReadFile(filepath.Join(sites, route.FQDN+".conf"))
	if string(after) != string(before) {
		t.Fatal("previous config file was not restored")
	}
	response := request("/")
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("restored live config is not serving the old policy")
	}
	occupied.Close()
	if code, result := mgr.Apply(context.Background(), route); code != 200 || !result.Applied {
		t.Fatalf("same-generation retry failed: %d/%+v", code, result)
	}
	response = request("/")
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatalf("confirmed configuration did not deny new connection: %d", response.StatusCode)
	}
	close(finish)
	remaining, err := io.ReadAll(reader)
	if err != nil || string(remaining) != "finished\n" {
		t.Fatalf("active response interrupted: %q/%v", remaining, err)
	}
}

func TestSyncAllPreservesPrivateReloadProof(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, nginx.ReloadProofConfig)
	if err := os.WriteFile(path, []byte("private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	code, result := h.mgr.SyncAll(context.Background(), model.SyncAllRequest{SnapshotGeneration: 1, Routes: []model.Route{}})
	if code != 200 || len(result.Pruned) != 0 {
		t.Fatalf("private receipt pruned: %d/%+v", code, result)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "private fixture" {
		t.Fatal("private proof file changed")
	}
}
