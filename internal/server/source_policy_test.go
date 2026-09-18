package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/config"
	"github.com/pnuops/pickle-proxy-agent/internal/fake"
	"github.com/pnuops/pickle-proxy-agent/internal/manager"
	"github.com/pnuops/pickle-proxy-agent/internal/render"
	"github.com/pnuops/pickle-proxy-agent/internal/state"
)

func TestSourcePolicyWireReachesApplyAndInvalidSyncPreservesFiles(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Load(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	ng := &fake.Nginx{}
	params := render.Params{HTTPSListen: "127.0.0.1:8443", LECertRef: "letsencrypt", WildcardCerts: map[string]render.CertPair{"pusan.dev": {Cert: "/c.pem", Key: "/k.pem"}}, Webroot: "/acme"}
	h := New(config.Config{Token: testToken, AllowedSources: []string{testSrc}}, manager.New(dir, params, "/le", ng, fake.NewCertbot(), store)).Handler()
	encoded, _ := json.Marshal(platformBody())
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	apply := func(path string, body any) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req(http.MethodPost, path, testToken, testSrc, body))
		return w.Code
	}
	if code := apply("/apply", body); code != 200 {
		t.Fatalf("legacy status %d", code)
	}
	path := filepath.Join(dir, platformBody().FQDN+".conf")
	legacy, _ := os.ReadFile(path)
	if strings.Contains(string(legacy), "deny all;") {
		t.Fatal("legacy policy changed")
	}
	body["generation"] = 8
	body["sourcePolicy"] = map[string]any{"allowedCidrs": []string{}}
	if code := apply("/apply", body); code != 200 {
		t.Fatalf("deny status %d", code)
	}
	denied, _ := os.ReadFile(path)
	if !strings.Contains(string(denied), "deny all;") {
		t.Fatal("JSON policy did not reach nginx")
	}
	body["generation"] = 9
	for _, invalid := range []any{nil, map[string]any{}, map[string]any{"allowedCidrs": nil}, map[string]any{"allowedCidrs": []string{"192.0.2.1/24"}}} {
		body["sourcePolicy"] = invalid
		for _, endpoint := range []string{"/apply", "/sync-all"} {
			var payload any = body
			if endpoint == "/sync-all" {
				payload = map[string]any{"snapshotGeneration": 10, "routes": []any{body}}
			}
			if code := apply(endpoint, payload); code != 400 {
				t.Fatalf("%s invalid policy status %d", endpoint, code)
			}
		}
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(denied) {
		t.Fatal("rejected policy changed published files")
	}
	if tests, reloads := ng.Counts(); tests != 2 || reloads != 2 {
		t.Fatalf("unexpected nginx calls %d/%d", tests, reloads)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(http.MethodGet, "/status", testToken, testSrc, nil))
	if !strings.Contains(w.Body.String(), `"capabilities":["source-acl-v1"]`) {
		t.Fatalf("capability absent: %s", w.Body.String())
	}
}
