package render

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pnuops/pickle-proxy-agent/internal/sourcepolicy"
)

// This optional test runs a real nginx in an isolated test environment. The
// explicit binary setting avoids accidentally launching a host's service.
func TestSourcePolicyNginxEnforcesClientAddress(t *testing.T) {
	binary := os.Getenv("PICKLE_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("set PICKLE_TEST_NGINX_BIN in an isolated nginx test environment")
	}
	for _, tc := range []struct {
		name           string
		platform       bool
		ready          bool
		proxyHTTP      bool
		untrustedProxy bool
		allowDirect    bool
	}{
		{name: "platform TLS", platform: true, ready: true},
		{name: "custom TLS", ready: true},
		{name: "custom HTTP fallback"},
		{name: "custom HTTP trusted PROXY", proxyHTTP: true},
		{name: "custom direct HTTP allowed", allowDirect: true},
		{name: "custom HTTP untrusted PROXY", proxyHTTP: true, untrustedProxy: true},
		{name: "custom HTTP untrusted PROXY with allowed actual peer", proxyHTTP: true, untrustedProxy: true, allowDirect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			webroot := filepath.Join(dir, "acme")
			challenge := filepath.Join(webroot, ".well-known", "acme-challenge")
			if err := os.MkdirAll(challenge, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(challenge, "test-token"), []byte("challenge"), 0644); err != nil {
				t.Fatal(err)
			}
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"real": r.Header.Get("X-Real-IP"), "xff": r.Header.Get("X-Forwarded-For"), "forwarded": r.Header.Get("Forwarded")})
			}))
			defer backend.Close()
			assertBackend := func(body, actual string) {
				t.Helper()
				var headers map[string]string
				if err := json.Unmarshal([]byte(body), &headers); err != nil {
					t.Fatalf("backend body %q: %v", body, err)
				}
				if headers["real"] != actual || headers["xff"] != actual || headers["forwarded"] != "" {
					t.Fatalf("backend trusted forged headers: %+v, expected %s", headers, actual)
				}
			}
			cert, key := nginxTestCertificate(t, dir)
			httpAddress, tlsAddress := unusedTestAddress(t), unusedTestAddress(t)
			p := testParams()
			p.HTTPSListen, p.Webroot, p.SiteLimits = tlsAddress, webroot, false
			if tc.proxyHTTP {
				p.HTTPProxyListen = unusedTestAddress(t)
				p.HTTPProxyTrustedPeers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
				if tc.untrustedProxy {
					p.HTTPProxyTrustedPeers = []netip.Addr{netip.MustParseAddr("198.51.100.99")}
				}
			}
			r := customRoute()
			if tc.platform {
				r = platformRoute()
			}
			allowed := []string{"192.0.2.0/24", "2001:db8::/32"}
			if tc.allowDirect {
				allowed = []string{"127.0.0.1/32"}
			}
			policy, err := sourcepolicy.FromCIDRs(allowed)
			if err != nil {
				t.Fatal(err)
			}
			r.SourcePolicy = policy
			vhost, err := Render(r, p, cert, key, tc.ready)
			if err != nil {
				t.Fatal(err)
			}
			vhost = strings.ReplaceAll(vhost, "listen 80;", "listen "+httpAddress+";")
			// A loopback backend observes the actual forwarding headers after nginx's
			// access phase without requiring a guest network in the test container.
			upstream := fmt.Sprintf("proxy_pass http://%s:%d;", r.TargetIP, r.TargetPort)
			vhost = strings.ReplaceAll(vhost, upstream, "proxy_pass "+backend.URL+";")
			// An unrelated base config must not make a policy trust client HTTP headers.
			configuration := "daemon off;\nmaster_process off;\npid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp {\naccess_log off;\nset_real_ip_from 127.0.0.1; real_ip_header X-Forwarded-For;\nmap $http_upgrade $connection_upgrade { default upgrade; '' close; }\n" + vhost + "}\n"
			confPath := filepath.Join(dir, "nginx.conf")
			if err := os.WriteFile(confPath, []byte(configuration), 0600); err != nil {
				t.Fatal(err)
			}
			address := httpAddress
			if tc.ready {
				address = tlsAddress
			}
			if tc.proxyHTTP {
				address = p.HTTPProxyListen
			}
			startTestNginx(t, binary, confPath, dir, address)
			if tc.ready || tc.proxyHTTP {
				for _, request := range []struct {
					source    string
					forwarded string
					status    int
				}{
					{"192.0.2.7", "198.51.100.1", http.StatusOK},
					{"198.51.100.1", "192.0.2.7", http.StatusForbidden},
					{"2001:db8::7", "198.51.100.1", http.StatusOK},
					{"2001:db9::1", "2001:db8::7", http.StatusForbidden},
				} {
					if tc.untrustedProxy {
						request.status = http.StatusForbidden
						if tc.allowDirect {
							request.status = http.StatusOK
						}
					}
					status, body := requestTestNginxProtocol(t, address, r.FQDN, "/", request.source, request.forwarded, tc.ready)
					if status != request.status {
						t.Fatalf("source %s status/body = %d/%q", request.source, status, body)
					}
					if status == http.StatusOK {
						actual := request.source
						if tc.untrustedProxy {
							actual = "127.0.0.1"
						}
						assertBackend(body, actual)
					}
				}
			} else {
				status, body := requestTestNginx(t, address, r.FQDN, "/", "", "192.0.2.7")
				if tc.allowDirect {
					if status != http.StatusOK {
						t.Fatalf("direct source status %d", status)
					}
					assertBackend(body, "127.0.0.1")
				} else if status != http.StatusForbidden {
					t.Fatalf("HTTP socket peer was allowed by forged XFF: %d", status)
				}
			}
			if !tc.platform {
				status, body := requestTestNginx(t, httpAddress, r.FQDN, "/.well-known/acme-challenge/test-token", "", "")
				if status != http.StatusOK || body != "challenge" {
					t.Fatalf("ACME blocked by site policy: %d/%q", status, body)
				}
			}
		})
	}
}

func unusedTestAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func nginxTestCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func startTestNginx(t *testing.T, binary, conf, dir, address string) {
	t.Helper()
	if output, err := exec.Command(binary, "-p", dir+"/", "-c", conf, "-t").CombinedOutput(); err != nil {
		t.Fatalf("nginx config test: %v\n%s", err, output)
	}
	logFile, err := os.Create(filepath.Join(dir, "nginx.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-p", dir+"/", "-c", conf)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = logFile.Close()
		if t.Failed() {
			log, _ := os.ReadFile(logFile.Name())
			t.Logf("nginx output:\n%s", log)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("nginx did not become ready")
}

func requestTestNginx(t *testing.T, address, host, path, proxySource, forwarded string) (int, string) {
	return requestTestNginxProtocol(t, address, host, path, proxySource, forwarded, proxySource != "")
}

func requestTestNginxProtocol(t *testing.T, address, host, path, proxySource, forwarded string, useTLS bool) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if proxySource != "" {
		_, port, _ := net.SplitHostPort(address)
		family, destination := "TCP4", "127.0.0.1"
		if netip.MustParseAddr(proxySource).Is6() {
			family, destination = "TCP6", "::1"
		}
		if _, err := fmt.Fprintf(conn, "PROXY %s %s %s 12345 %s\r\n", family, proxySource, destination, port); err != nil {
			t.Fatal(err)
		}
	}
	if useTLS {
		// The locally generated certificate exists only for this isolated test.
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+host+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	if forwarded != "" {
		req.Header.Set("X-Forwarded-For", forwarded)
		req.Header.Set("X-Real-IP", forwarded)
		req.Header.Set("Forwarded", "for="+forwarded)
	}
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}
