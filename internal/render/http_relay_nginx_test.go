package render

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// The optional external candidate is a complete source relay configuration.
// Its original URI remains local; the private metadata hop sees only HEAD/Host.
func TestNginxHTTPRelayAuthenticatesHostBeforeLocalRedirect(t *testing.T) {
	binary, candidate := os.Getenv("PICKLE_TEST_NGINX_BIN"), os.Getenv("PICKLE_TEST_SOURCE_HTTP_CANDIDATE")
	if binary == "" || candidate == "" {
		t.Skip("set explicit nginx and source HTTP candidate paths in an isolated test environment")
	}
	raw, err := os.ReadFile(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var observations []string
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		observations = append(observations, fmt.Sprintf("%s|%s|%s|%s|%s|%s", r.Method, r.Host, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("Cookie"), body))
		mu.Unlock()
		if r.Host == "outage.example" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Host != "site.example" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Path == "/__pickle_vm_host" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte("token"))
	}))
	defer metadata.Close()
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0755); err != nil {
		t.Fatal(err)
	}
	address := unusedTestAddress(t)
	text := strings.ReplaceAll(string(raw), "listen 80 default_server;", "listen "+address+" default_server;")
	text = strings.ReplaceAll(text, "    listen [::]:80 default_server;\n", "")
	// The optional external config owns its private origin; keep the fixture
	// independent of any deployment address and reject an ambiguous input.
	origins := regexp.MustCompile(`http://[A-Za-z0-9.:-]+:24080`).FindAllString(text, -1)
	if len(origins) != 2 || origins[0] != origins[1] {
		t.Fatal("candidate must use one metadata origin in both private locations")
	}
	text = strings.ReplaceAll(text, origins[0], metadata.URL)
	text = strings.ReplaceAll(text, "/etc/nginx/pickle-http-metadata-empty", empty)
	configuration := "daemon off;\nmaster_process off;\npid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log stderr;\nevents {}\nhttp { access_log off;\n" + text + "}\n"
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	startTestNginx(t, binary, conf, dir, address)
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	for _, tc := range []struct {
		host, path string
		status     int
	}{
		{"site.example", "/private?token=private", http.StatusMovedPermanently},
		{"unknown.example", "/private?token=private", http.StatusNotFound},
		{"outage.example", "/private?token=private", http.StatusServiceUnavailable},
	} {
		req, _ := http.NewRequest(http.MethodPost, "http://"+address+tc.path, strings.NewReader("private-body"))
		req.Host = tc.host
		req.Header.Set("Authorization", "Bearer private")
		req.Header.Set("Cookie", "session=private")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("%s returned %d, want %d", tc.host, response.StatusCode, tc.status)
		}
		if tc.status == http.StatusMovedPermanently && response.Header.Get("Location") != "https://"+tc.host+tc.path {
			t.Fatalf("redirect lost local original URI: %q", response.Header.Get("Location"))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observations) != 3 {
		t.Fatalf("metadata call count = %d", len(observations))
	}
	for _, observed := range observations {
		fields := strings.Split(observed, "|")
		var uri *url.URL
		if len(fields) == 6 {
			uri, err = url.ParseRequestURI(fields[2])
		}
		if strings.Contains(observed, "private") || len(fields) != 6 || fields[0] != http.MethodHead ||
			err != nil || uri == nil || uri.Path != "/__pickle_vm_host" || uri.RawQuery != "" ||
			fields[3] != "" || fields[4] != "" || fields[5] != "" {
			t.Fatalf("private hop forwarded original request fields: %q", observed)
		}
	}
}
