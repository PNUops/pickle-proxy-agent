package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/config"
	"github.com/pnuops/pickle-proxy-agent/internal/fake"
	"github.com/pnuops/pickle-proxy-agent/internal/manager"
	"github.com/pnuops/pickle-proxy-agent/internal/model"
	"github.com/pnuops/pickle-proxy-agent/internal/render"
	"github.com/pnuops/pickle-proxy-agent/internal/state"
)

const (
	testToken = "s3cr3t-proxy-token"
	testSrc   = "172.30.1.20"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"))
	params := render.Params{HTTPSListen: "127.0.0.1:8443", WildcardCert: "/c/full.pem", WildcardKey: "/c/key.pem", Webroot: "/var/www/certbot"}
	mgr := manager.New(dir, params, "/etc/letsencrypt/live", &fake.Nginx{}, fake.NewCertbot(), st)
	cfg := config.Config{Token: testToken, AllowedSources: []string{testSrc}, RateLimitPerMin: 0}
	return New(cfg, mgr).Handler()
}

// req builds a request with a controllable RemoteAddr (source IP) and auth header.
func req(method, path, token, src string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.RemoteAddr = src + ":54321"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestAuthFailClosed(t *testing.T) {
	h := newTestServer(t)
	route := platformBody()
	cases := []struct {
		name       string
		token, src string
		rawHeader  string // overrides Authorization when set
		wantStatus int
		wantCode   string
	}{
		{name: "no token", token: "", src: testSrc, wantStatus: 401, wantCode: "AUTH_TOKEN_INVALID"},
		{name: "wrong token", token: "nope", src: testSrc, wantStatus: 401, wantCode: "AUTH_TOKEN_INVALID"},
		{name: "wrong source", token: testToken, src: "172.30.1.99", wantStatus: 403, wantCode: "ACCESS_DENIED"},
		{name: "good", token: testToken, src: testSrc, wantStatus: 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := req(http.MethodPost, "/apply", c.token, c.src, route)
			if c.rawHeader != "" {
				r.Header.Set("Authorization", c.rawHeader)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, c.wantStatus, w.Body.String())
			}
			if c.wantCode != "" {
				var p model.Problem
				_ = json.Unmarshal(w.Body.Bytes(), &p)
				if p.Code != c.wantCode {
					t.Fatalf("code = %q, want %q", p.Code, c.wantCode)
				}
			}
		})
	}
}

func TestBlankBearerRejected(t *testing.T) {
	h := newTestServer(t)
	r := httptest.NewRequest(http.MethodPost, "/apply", bytes.NewReader(nil))
	r.RemoteAddr = testSrc + ":1"
	r.Header.Set("Authorization", "Bearer   ") // blank token after prefix
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("blank bearer => %d, want 401", w.Code)
	}
}

func TestEmptyTokenConfigDeniesAll(t *testing.T) {
	// A misconfigured (empty) server token must authenticate nobody, even with a
	// matching empty Authorization.
	dir := t.TempDir()
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"))
	mgr := manager.New(dir, render.Params{}, "/le", &fake.Nginx{}, fake.NewCertbot(), st)
	h := New(config.Config{Token: "", AllowedSources: []string{testSrc}}, mgr).Handler()
	r := req(http.MethodGet, "/status", "", testSrc, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("empty-token server => %d, want 401", w.Code)
	}
}

func TestEmptySourceAllowlistDeniesAll(t *testing.T) {
	dir := t.TempDir()
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"))
	mgr := manager.New(dir, render.Params{}, "/le", &fake.Nginx{}, fake.NewCertbot(), st)
	h := New(config.Config{Token: testToken, AllowedSources: nil}, mgr).Handler()
	r := req(http.MethodGet, "/status", testToken, testSrc, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("empty-allowlist server => %d, want 403", w.Code)
	}
}

func TestApplyResponseShape(t *testing.T) {
	h := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodPost, "/apply", testToken, testSrc, platformBody()))
	if w.Code != 200 {
		t.Fatalf("apply => %d %s", w.Code, w.Body.String())
	}
	var res model.ApplyResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.Applied || res.Generation != 7 {
		t.Fatalf("apply result = %+v", res)
	}
}

func TestStatusResponseShape(t *testing.T) {
	h := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/status", testToken, testSrc, nil))
	if w.Code != 200 {
		t.Fatalf("status => %d", w.Code)
	}
	var s model.StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Health != "ok" {
		t.Fatalf("health = %q", s.Health)
	}
}

func TestRateLimit429(t *testing.T) {
	dir := t.TempDir()
	st, _ := state.Load(filepath.Join(t.TempDir(), "state.json"))
	mgr := manager.New(dir, render.Params{}, "/le", &fake.Nginx{}, fake.NewCertbot(), st)
	// perMin=1 → burst 1: the second status call within the same instant is limited.
	h := New(config.Config{Token: testToken, AllowedSources: []string{testSrc}, RateLimitPerMin: 1}, mgr).Handler()
	first := httptest.NewRecorder()
	h.ServeHTTP(first, req(http.MethodGet, "/status", testToken, testSrc, nil))
	if first.Code != 200 {
		t.Fatalf("first status => %d", first.Code)
	}
	second := httptest.NewRecorder()
	h.ServeHTTP(second, req(http.MethodGet, "/status", testToken, testSrc, nil))
	if second.Code != 429 {
		t.Fatalf("second status => %d, want 429", second.Code)
	}
}

func platformBody() model.Route {
	return model.Route{FQDN: "team-alpha-a1b2.pickle.pnuops.com", DesiredState: model.Present, Generation: 7, TargetIP: "172.29.4.11", TargetPort: 8080, CertRef: model.CertRefWildcard}
}
