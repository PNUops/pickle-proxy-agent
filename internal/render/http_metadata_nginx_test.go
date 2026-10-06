package render

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

func TestNginxMetadataDoesNotReachBackendOrTrustForwardingHeaders(t *testing.T) {
	binary := os.Getenv("PICKLE_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("set PICKLE_TEST_NGINX_BIN in an isolated nginx test environment")
	}
	for _, untrusted := range []bool{false, true} {
		t.Run(fmt.Sprintf("untrusted=%t", untrusted), func(t *testing.T) {
			dir := t.TempDir()
			challenge := filepath.Join(dir, "acme", ".well-known", "acme-challenge")
			if err := os.MkdirAll(challenge, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(challenge, "test-token"), []byte("token"), 0644); err != nil {
				t.Fatal(err)
			}
			var hits atomic.Int64
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte("backend"))
			}))
			defer backend.Close()
			p := testParams()
			p.Webroot, p.SiteLimits = filepath.Join(dir, "acme"), false
			p.HTTPMetadataListen = unusedTestAddress(t)
			p.HTTPMetadataTrustedPeers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
			if untrusted {
				p.HTTPMetadataTrustedPeers = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
			}
			r := customRoute()
			policy, err := sourcepolicy.FromCIDRs([]string{"198.51.100.0/24"})
			if err != nil {
				t.Fatal(err)
			}
			r.SourcePolicy = policy
			vhost, err := Render(r, p, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			vhost = strings.ReplaceAll(vhost, "listen 80;", "listen "+unusedTestAddress(t)+";")
			vhost = strings.ReplaceAll(vhost, fmt.Sprintf("proxy_pass http://%s:%d;", r.TargetIP, r.TargetPort), "proxy_pass "+backend.URL+";")
			defaultServer := "server { listen " + p.HTTPMetadataListen + " default_server; server_name _; return 404; }\n"
			configuration := "daemon off;\nmaster_process off;\npid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp { access_log off;\nset_real_ip_from 127.0.0.1; real_ip_header X-Forwarded-For;\nmap $http_upgrade $connection_upgrade { default upgrade; '' close; }\n" + defaultServer + vhost + "}\n"
			conf := filepath.Join(dir, "nginx.conf")
			if err := os.WriteFile(conf, []byte(configuration), 0600); err != nil {
				t.Fatal(err)
			}
			startTestNginx(t, binary, conf, dir, p.HTTPMetadataListen)
			for _, request := range []struct {
				method, host, path string
				status             int
			}{
				{http.MethodHead, r.FQDN, "/__pickle_vm_host", http.StatusNoContent},
				{http.MethodGet, r.FQDN, "/__pickle_vm_host", http.StatusMethodNotAllowed},
				{http.MethodHead, r.FQDN, "/__pickle_vm_host?token=private", http.StatusNotFound},
				{http.MethodGet, r.FQDN, "/.well-known/acme-challenge/test-token", http.StatusOK},
				{http.MethodPost, r.FQDN, "/.well-known/acme-challenge/test-token", http.StatusMethodNotAllowed},
				{http.MethodHead, r.FQDN, "/", http.StatusNotFound},
				{http.MethodHead, "unknown.example", "/__pickle_vm_host", http.StatusNotFound},
			} {
				req, err := http.NewRequest(request.method, "http://"+p.HTTPMetadataListen+request.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = request.host
				req.Header.Set("X-Forwarded-For", "192.0.2.10")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				want := request.status
				if untrusted && request.host == r.FQDN {
					want = http.StatusForbidden
				}
				if resp.StatusCode != want {
					t.Fatalf("%s %s/%s = %d, want %d", request.method, request.host, request.path, resp.StatusCode, want)
				}
			}
			if hits.Load() != 0 {
				t.Fatalf("metadata/ACME request reached backend %d times", hits.Load())
			}
		})
	}
}
