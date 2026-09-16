package render

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		name     string
		platform bool
		ready    bool
	}{
		{"platform TLS", true, true},
		{"custom TLS", false, true},
		{"custom HTTP fallback", false, false},
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
			backend := filepath.Join(dir, "site")
			if err := os.Mkdir(backend, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(backend, "index.html"), []byte("site"), 0644); err != nil {
				t.Fatal(err)
			}
			cert, key := nginxTestCertificate(t, dir)
			httpAddress, tlsAddress := unusedTestAddress(t), unusedTestAddress(t)
			p := testParams()
			p.HTTPSListen, p.Webroot, p.SiteLimits = tlsAddress, webroot, false
			r := customRoute()
			if tc.platform {
				r = platformRoute()
			}
			policy, err := sourcepolicy.Parse([]string{"192.0.2.0/24"})
			if err != nil {
				t.Fatal(err)
			}
			vhost, err := renderWithSourcePolicy(r, p, cert, key, tc.ready, policy)
			if err != nil {
				t.Fatal(err)
			}
			vhost = strings.ReplaceAll(vhost, "listen 80;", "listen "+httpAddress+";")
			// Static content exercises nginx's actual access phase without requiring
			// a routable guest network in the isolated test container.
			upstream := fmt.Sprintf("proxy_pass http://%s:%d;", r.TargetIP, r.TargetPort)
			vhost = strings.ReplaceAll(vhost, upstream, "root "+backend+";")
			configuration := "daemon off;\nmaster_process off;\npid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp {\naccess_log off;\nmap $http_upgrade $connection_upgrade { default upgrade; '' close; }\n" + vhost + "}\n"
			confPath := filepath.Join(dir, "nginx.conf")
			if err := os.WriteFile(confPath, []byte(configuration), 0600); err != nil {
				t.Fatal(err)
			}
			address := httpAddress
			if tc.ready {
				address = tlsAddress
			}
			startTestNginx(t, binary, confPath, dir, address)
			if tc.ready {
				for _, request := range []struct {
					source    string
					forwarded string
					status    int
				}{
					{"192.0.2.7", "198.51.100.1", http.StatusOK},
					{"198.51.100.1", "192.0.2.7", http.StatusForbidden},
				} {
					status, body := requestTestNginx(t, address, r.FQDN, "/", request.source, request.forwarded)
					if status != request.status || status == http.StatusOK && body != "site" {
						t.Fatalf("TLS source %s status/body = %d/%q", request.source, status, body)
					}
				}
			} else {
				status, _ := requestTestNginx(t, address, r.FQDN, "/", "", "192.0.2.7")
				if status != http.StatusForbidden {
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
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
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
		if _, err := fmt.Fprintf(conn, "PROXY TCP4 %s 127.0.0.1 12345 %s\r\n", proxySource, port); err != nil {
			t.Fatal(err)
		}
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
