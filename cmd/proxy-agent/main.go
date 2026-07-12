// Command proxy-agent is the reverse-proxy control daemon that runs on LXC 100.
// It receives desired routing state from pickle-api over the internal bridge and
// renders it into nginx vhosts (docs/api/internal.md Link 2, docs/plan/06-domains-tls.md).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pnuops/pickle-proxy-agent/internal/certbot"
	"github.com/pnuops/pickle-proxy-agent/internal/config"
	"github.com/pnuops/pickle-proxy-agent/internal/manager"
	"github.com/pnuops/pickle-proxy-agent/internal/nginx"
	"github.com/pnuops/pickle-proxy-agent/internal/render"
	"github.com/pnuops/pickle-proxy-agent/internal/server"
	"github.com/pnuops/pickle-proxy-agent/internal/state"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(cfg.NginxDir, 0o750); err != nil {
		log.Fatalf("nginx dir %s: %v", cfg.NginxDir, err)
	}

	st, err := state.Load(cfg.StateFile)
	if err != nil {
		log.Fatalf("state: %v", err)
	}

	params := render.Params{
		HTTPSListen:   cfg.HTTPSListen,
		WildcardCert:  cfg.WildcardCert,
		WildcardKey:   cfg.WildcardKey,
		Webroot:       cfg.Webroot,
		RealIPInclude: cfg.RealIPInclude,
	}
	ng := nginx.New(cfg.NginxBin, cfg.ExecTimeout)
	cb := certbot.New(cfg.CertbotBin, cfg.Webroot, cfg.LEDir, cfg.CertbotEmail, cfg.ExecTimeout)
	mgr := manager.New(cfg.NginxDir, params, cfg.LEDir, ng, cb, st)

	srv := server.New(cfg, mgr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("pickle-proxy-agent listening on %s (nginx dir %s)", cfg.Listen, cfg.NginxDir)
	if err := server.Run(ctx, cfg.Listen, srv.Handler()); err != nil {
		log.Fatalf("server: %v", err)
	}
	log.Print("pickle-proxy-agent stopped")
}
