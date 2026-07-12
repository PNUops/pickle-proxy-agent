// Package server exposes the agent's HTTP control surface: POST /apply,
// POST /sync-all, GET /status (docs/api/internal.md, Link 2). Every route is behind
// the fail-closed source-IP + bearer-token guard and a per-key rate limiter.
package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/pnuops/pickle-proxy-agent/internal/config"
	"github.com/pnuops/pickle-proxy-agent/internal/manager"
	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

// Server is the HTTP control server.
type Server struct {
	mgr   *manager.Manager
	auth  authConfig
	limit *limiter
}

// New wires a Server from config and a manager.
func New(cfg config.Config, mgr *manager.Manager) *Server {
	return &Server{
		mgr:   mgr,
		auth:  newAuth(cfg.Token, cfg.AllowedSources),
		limit: newLimiter(cfg.RateLimitPerMin),
	}
}

// Handler returns the fully wired http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apply", s.auth.guard(s.handleApply))
	mux.HandleFunc("POST /sync-all", s.auth.guard(s.handleSyncAll))
	mux.HandleFunc("GET /status", s.auth.guard(s.handleStatus))
	return mux
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	var route model.Route
	if err := decodeJSON(w, r, &route); err != nil {
		writeJSON(w, http.StatusBadRequest, model.ApplyResult{Applied: false, Error: err.Error()})
		return
	}
	if route.FQDN == "" {
		writeJSON(w, http.StatusBadRequest, model.ApplyResult{Applied: false, Error: "fqdn is required"})
		return
	}
	if !s.limit.allow("apply:" + route.FQDN) {
		writeRetry(w)
		return
	}
	code, res := s.mgr.Apply(r.Context(), route)
	writeJSON(w, code, res)
}

func (s *Server) handleSyncAll(w http.ResponseWriter, r *http.Request) {
	var req model.SyncAllRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, model.SyncAllResult{Applied: false, Error: err.Error()})
		return
	}
	if !s.limit.allow("sync:" + sourceKey(r.RemoteAddr)) {
		writeRetry(w)
		return
	}
	code, res := s.mgr.SyncAll(r.Context(), req)
	writeJSON(w, code, res)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.limit.allow("status:" + sourceKey(r.RemoteAddr)) {
		writeRetry(w)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status())
}

// Run starts the HTTP server on cfg.Listen until ctx is cancelled.
func Run(ctx context.Context, listen string, h http.Handler) error {
	srv := &http.Server{Addr: listen, Handler: h}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		return err
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRetry(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeProblem(w, http.StatusTooManyRequests, "RATE_LIMITED")
}
