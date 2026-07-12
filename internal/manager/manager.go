// Package manager owns the reverse-proxy control logic: it serializes every config
// mutation, renders vhosts, validates with nginx, swaps atomically, rolls back on any
// failure, and persists the per-FQDN generation that makes stale requests a no-op.
//
// Correctness contract (docs/api/internal.md, Link 2):
//   - all mutations run one at a time (mutateMu) — one render→test→swap→reload cycle;
//   - a request whose generation ≤ the applied generation is rejected 409 (a late
//     retry can never resurrect an old vhost onto a reused IP);
//   - apply/sync are all-or-nothing: on nginx -t / reload failure the previous file
//     state is restored and the running nginx is never reloaded onto a bad candidate;
//   - /sync-all is authoritative: agent-managed files absent from the manifest are
//     pruned. The agent touches only /etc/nginx/pickle.d/*.conf.
package manager

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pnuops/pickle-proxy-agent/internal/certbot"
	"github.com/pnuops/pickle-proxy-agent/internal/model"
	"github.com/pnuops/pickle-proxy-agent/internal/nginx"
	"github.com/pnuops/pickle-proxy-agent/internal/render"
	"github.com/pnuops/pickle-proxy-agent/internal/state"
)

// Manager coordinates rendering, nginx, cert issuance, and persisted generations.
type Manager struct {
	dir     string // /etc/nginx/pickle.d
	params  render.Params
	leDir   string
	nginx   nginx.Nginx
	certbot certbot.Provider
	store   *state.Store

	mutateMu sync.Mutex // serializes all config mutations (the single queue)

	evMu      sync.Mutex
	startedAt time.Time
	lastApply *model.Event
	lastSync  *model.Event

	now func() time.Time
}

// New builds a Manager. dir must already exist.
func New(dir string, params render.Params, leDir string, n nginx.Nginx, cb certbot.Provider, st *state.Store) *Manager {
	return &Manager{
		dir:       dir,
		params:    params,
		leDir:     leDir,
		nginx:     n,
		certbot:   cb,
		store:     st,
		startedAt: time.Now(),
		now:       time.Now,
	}
}

func (m *Manager) pathFor(fqdn string) string {
	return filepath.Join(m.dir, render.FileName(fqdn))
}

// Apply handles POST /apply. It returns an HTTP status code and the response body.
func (m *Manager) Apply(ctx context.Context, r model.Route) (int, model.ApplyResult) {
	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	// Stale-reject: generation ≤ applied is a superseded no-op.
	if applied, known := m.store.Generation(r.FQDN); known && r.Generation <= applied {
		return 409, model.ApplyResult{Applied: false, Generation: applied}
	}
	if err := render.Validate(r); err != nil {
		return 422, model.ApplyResult{Applied: false, Error: err.Error()}
	}

	path := m.pathFor(r.FQDN)
	backup, existed, err := readFileMaybe(path)
	if err != nil {
		return 422, model.ApplyResult{Applied: false, Error: err.Error()}
	}
	restore := func() { restoreFile(path, backup, existed) }

	if r.DesiredState == model.Absent {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return 422, model.ApplyResult{Applied: false, Error: err.Error()}
		}
		if out, err := m.testAndReload(ctx); err != nil {
			restore()
			m.recordApply(false, "remove "+r.FQDN, out)
			return 422, model.ApplyResult{Applied: false, Error: out}
		}
		_ = m.store.Record(r.FQDN, state.Entry{Generation: r.Generation, Present: false, AppliedAt: m.now()})
		m.recordApply(true, "remove "+r.FQDN, "")
		return 200, model.ApplyResult{Applied: true, Generation: r.Generation}
	}

	// PRESENT.
	certPath, keyPath := render.CertPaths(r, m.params, m.leDir)
	certReady := render.IsPlatform(r.CertRef) || m.certbot.Exists(r.FQDN)
	content, err := render.Render(r, m.params, certPath, keyPath, certReady)
	if err != nil {
		return 422, model.ApplyResult{Applied: false, Error: err.Error()}
	}
	if err := writeFile(path, content); err != nil {
		return 422, model.ApplyResult{Applied: false, Error: err.Error()}
	}
	if out, err := m.testAndReload(ctx); err != nil {
		restore()
		m.recordApply(false, r.FQDN, out)
		return 422, model.ApplyResult{Applied: false, Error: out}
	}
	_ = m.store.Record(r.FQDN, state.Entry{Generation: r.Generation, Present: true, AppliedAt: m.now()})

	// Custom domains: drive certbot after the (challenge) vhost is live, then upgrade
	// to the full HTTPS vhost. Cert failures do not fail the apply — the vhost is live
	// and the failure is surfaced on /status.
	if !render.IsPlatform(r.CertRef) {
		m.settleCert(ctx, r, path, certReady, certPath, keyPath)
	}
	m.recordApply(true, r.FQDN, "")
	return 200, model.ApplyResult{Applied: true, Generation: r.Generation}
}

// settleCert ensures the LE cert for a custom domain and upgrades the vhost to HTTPS.
// Must be called with mutateMu held.
func (m *Manager) settleCert(ctx context.Context, r model.Route, path string, certReady bool, certPath, keyPath string) {
	if certReady {
		_ = m.store.SetCert(r.FQDN, model.CertOK, "")
		return
	}
	if err := m.certbot.Ensure(ctx, r.FQDN); err != nil {
		_ = m.store.SetCert(r.FQDN, model.CertFailed, err.Error())
		return
	}
	// Cert now exists — upgrade challenge vhost to full HTTPS.
	upgraded, rerr := render.Render(r, m.params, certPath, keyPath, true)
	if rerr != nil {
		_ = m.store.SetCert(r.FQDN, model.CertFailed, rerr.Error())
		return
	}
	backup, existed, _ := readFileMaybe(path)
	if err := writeFile(path, upgraded); err != nil {
		_ = m.store.SetCert(r.FQDN, model.CertFailed, err.Error())
		return
	}
	if out, err := m.testAndReload(ctx); err != nil {
		restoreFile(path, backup, existed) // keep the working challenge vhost live
		_ = m.store.SetCert(r.FQDN, model.CertFailed, out)
		return
	}
	_ = m.store.SetCert(r.FQDN, model.CertOK, "")
}

// SyncAll handles POST /sync-all: the manifest is authoritative.
func (m *Manager) SyncAll(ctx context.Context, req model.SyncAllRequest) (int, model.SyncAllResult) {
	m.mutateMu.Lock()
	defer m.mutateMu.Unlock()

	if last := m.store.SnapshotGeneration(); last != 0 && req.SnapshotGeneration <= last {
		return 409, model.SyncAllResult{Applied: false, SnapshotGeneration: last}
	}

	// Render every entry up front; any validation/render error aborts before touching disk.
	desired := make(map[string]string, len(req.Routes)) // filename -> content
	newEntries := make(map[string]state.Entry, len(req.Routes))
	pendingCustom := make([]model.Route, 0)
	for _, r := range req.Routes {
		if r.DesiredState == model.Absent {
			// A snapshot lists what should exist; ABSENT entries are simply omitted.
			continue
		}
		if err := render.Validate(r); err != nil {
			return 422, model.SyncAllResult{Applied: false, SnapshotGeneration: req.SnapshotGeneration, Error: r.FQDN + ": " + err.Error()}
		}
		certPath, keyPath := render.CertPaths(r, m.params, m.leDir)
		certReady := render.IsPlatform(r.CertRef) || m.certbot.Exists(r.FQDN)
		content, err := render.Render(r, m.params, certPath, keyPath, certReady)
		if err != nil {
			return 422, model.SyncAllResult{Applied: false, SnapshotGeneration: req.SnapshotGeneration, Error: r.FQDN + ": " + err.Error()}
		}
		fn := render.FileName(r.FQDN)
		if _, dup := desired[fn]; dup {
			return 422, model.SyncAllResult{Applied: false, SnapshotGeneration: req.SnapshotGeneration, Error: "duplicate fqdn " + r.FQDN}
		}
		desired[fn] = content
		cs := model.CertState("")
		if !render.IsPlatform(r.CertRef) {
			cs = model.CertOK
			if !certReady {
				cs = model.CertPending
				pendingCustom = append(pendingCustom, r)
			}
		}
		newEntries[r.FQDN] = state.Entry{Generation: r.Generation, Present: true, AppliedAt: m.now(), CertState: cs}
	}

	// Snapshot the current agent-managed tree so we can restore on failure, and
	// compute the prune set (agent-managed files not in the manifest).
	prior, err := readConfDir(m.dir)
	if err != nil {
		return 422, model.SyncAllResult{Applied: false, SnapshotGeneration: req.SnapshotGeneration, Error: err.Error()}
	}
	var pruned []string
	for fn := range prior {
		if _, keep := desired[fn]; !keep {
			pruned = append(pruned, strings.TrimSuffix(fn, ".conf"))
		}
	}
	sort.Strings(pruned)

	// Swap: write the full desired set, remove everything else agent-managed.
	if err := writeConfDir(m.dir, desired); err != nil {
		restoreConfDir(m.dir, prior)
		return 422, model.SyncAllResult{Applied: false, SnapshotGeneration: req.SnapshotGeneration, Error: err.Error()}
	}
	if out, err := m.testAndReload(ctx); err != nil {
		restoreConfDir(m.dir, prior)
		m.recordSync(false, "sync-all", out)
		return 422, model.SyncAllResult{Applied: false, SnapshotGeneration: req.SnapshotGeneration, Error: out}
	}
	_ = m.store.ReplaceAll(newEntries, req.SnapshotGeneration)

	// Best-effort cert issuance for custom domains whose cert was not yet present.
	for _, r := range pendingCustom {
		certPath, keyPath := render.CertPaths(r, m.params, m.leDir)
		m.settleCert(ctx, r, m.pathFor(r.FQDN), false, certPath, keyPath)
	}

	results := make([]model.FQDNResult, 0, len(newEntries))
	for fqdn, e := range newEntries {
		results = append(results, model.FQDNResult{FQDN: fqdn, Applied: true, Generation: e.Generation})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].FQDN < results[j].FQDN })
	m.recordSync(true, "sync-all", "")
	return 200, model.SyncAllResult{Applied: true, SnapshotGeneration: req.SnapshotGeneration, Pruned: pruned, Results: results}
}

// testAndReload validates the on-disk config, then reloads only if valid.
func (m *Manager) testAndReload(ctx context.Context) (string, error) {
	out, err := m.nginx.Test(ctx)
	if err != nil {
		return out, err
	}
	if err := m.nginx.Reload(ctx); err != nil {
		msg := strings.TrimSpace(out + "\nreload: " + err.Error())
		return msg, err
	}
	return out, nil
}

// Status handles GET /status.
func (m *Manager) Status() model.StatusResponse {
	m.evMu.Lock()
	la, ls := m.lastApply, m.lastSync
	started := m.startedAt
	m.evMu.Unlock()

	snap := m.store.Snapshot()
	routes := make([]model.RouteStatus, 0, len(snap))
	var certs []model.CertStatus
	for fqdn, e := range snap {
		routes = append(routes, model.RouteStatus{FQDN: fqdn, Present: e.Present, Generation: e.Generation, AppliedAt: e.AppliedAt})
		if e.CertState != "" {
			certs = append(certs, model.CertStatus{FQDN: fqdn, State: e.CertState, CheckedAt: e.CertAt, Error: e.CertError})
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].FQDN < routes[j].FQDN })
	sort.Slice(certs, func(i, j int) bool { return certs[i].FQDN < certs[j].FQDN })
	return model.StatusResponse{
		Health:    "ok",
		StartedAt: started,
		Now:       m.now(),
		LastApply: la,
		LastSync:  ls,
		Routes:    routes,
		Certs:     certs,
	}
}

func (m *Manager) recordApply(ok bool, detail, errStr string) {
	m.evMu.Lock()
	m.lastApply = &model.Event{At: m.now(), OK: ok, Detail: detail, Error: errStr}
	m.evMu.Unlock()
}

func (m *Manager) recordSync(ok bool, detail, errStr string) {
	m.evMu.Lock()
	m.lastSync = &model.Event{At: m.now(), OK: ok, Detail: detail, Error: errStr}
	m.evMu.Unlock()
}
