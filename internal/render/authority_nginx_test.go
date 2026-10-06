package render

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNginxRejectsUnknownSNIAndRawHostBeforeSiteBackend(t *testing.T) {
	binary := os.Getenv("PICKLE_TEST_NGINX_BIN")
	if binary == "" {
		t.Skip("set PICKLE_TEST_NGINX_BIN in an isolated nginx test environment")
	}
	dir := t.TempDir()
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("site"))
	}))
	defer backend.Close()
	p := testParams()
	p.SiteLimits = false
	p.HTTPSListen = unusedTestAddress(t)
	p.IngressMarker = filepath.Join(dir, "site-enabled")
	r := platformRoute()
	cert, key := nginxTestCertificate(t, dir)
	vhost, err := Render(r, p, cert, key, true)
	if err != nil {
		t.Fatal(err)
	}
	vhost = strings.ReplaceAll(vhost, fmt.Sprintf("proxy_pass http://%s:%d;", r.TargetIP, r.TargetPort), "proxy_pass "+backend.URL+";")
	defaults := "server { listen " + p.HTTPSListen + " ssl proxy_protocol default_server; http2 on; ssl_reject_handshake on; return 444; }\n"
	configuration := "daemon off;\nmaster_process off;\npid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp { access_log off; map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n" + defaults + vhost + "}\n"
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	startTestNginx(t, binary, conf, dir, p.HTTPSListen)
	request := func(sni, host string) (int, error) {
		conn, err := net.DialTimeout("tcp", p.HTTPSListen, time.Second)
		if err != nil {
			return 0, err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, port, _ := net.SplitHostPort(p.HTTPSListen)
		_, _ = fmt.Fprintf(conn, "PROXY TCP4 192.0.2.7 127.0.0.1 12345 %s\r\n", port)
		// The certificate is created only for this isolated test fixture.
		secure := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: sni})
		if err := secure.Handshake(); err != nil {
			return 0, err
		}
		_, _ = fmt.Fprintf(secure, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		response, err := http.ReadResponse(bufio.NewReader(secure), nil)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		return response.StatusCode, nil
	}
	if code, err := request(r.FQDN, r.FQDN); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("absent marker = %d %v", code, err)
	}
	if code, err := request("unknown.example", "unknown.example"); err == nil {
		t.Fatalf("unknown SNI completed TLS with status %d", code)
	}
	if code, err := request(r.FQDN, "unknown.example"); err != nil || code != http.StatusMisdirectedRequest {
		// The explicit unknown-host default may close the established connection
		// with nginx 444; a known virtual host instead returns the authority 421.
		if err == nil || !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("known SNI/unknown Host was not denied = %d %v", code, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("authority or marker denial reached the site backend")
	}
	if err := os.WriteFile(p.IngressMarker, []byte("enabled"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := request(r.FQDN, r.FQDN); err != nil || code != http.StatusOK {
		t.Fatalf("enabled exact authority = %d %v", code, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("site backend hit count = %d", hits.Load())
	}
}
