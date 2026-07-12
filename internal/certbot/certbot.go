// Package certbot obtains and inspects Let's Encrypt certificates for custom domains
// via the webroot HTTP-01 challenge.
//
// It is an interface (Provider) so the manager can be tested without hitting Let's
// Encrypt: the fake in tests simply materialises cert files (or reports failure). The
// real provider shells out to certbot in --webroot mode against the same webroot the
// challenge vhost serves, then relies on certbot's own systemd renewal timer for
// ongoing renewals (renewal failures surface on GET /status). A renewal deploy-hook
// installed by scripts/deploy.sh (/etc/letsencrypt/renewal-hooks/deploy/
// pickle-nginx-reload.sh) reloads nginx after each successful renewal so the renewed
// certificate is served without waiting for the next apply/sync.
package certbot

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Provider issues and inspects custom-domain certificates.
type Provider interface {
	// Exists reports whether a usable cert+key already exist for fqdn.
	Exists(fqdn string) bool
	// Ensure obtains (HTTP-01 webroot) a cert for fqdn if absent. It returns nil
	// once the cert exists on disk. Called only after the challenge vhost is live.
	Ensure(ctx context.Context, fqdn string) error
}

// Certbot is the production Provider.
type Certbot struct {
	Bin     string
	Webroot string
	LEDir   string // /etc/letsencrypt/live
	Email   string
	Timeout time.Duration
}

// New returns a Certbot provider.
func New(bin, webroot, leDir, email string, timeout time.Duration) *Certbot {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Certbot{Bin: bin, Webroot: webroot, LEDir: leDir, Email: email, Timeout: timeout}
}

// paths returns the fullchain/privkey paths certbot writes for fqdn.
func (c *Certbot) paths(fqdn string) (cert, key string) {
	base := filepath.Join(c.LEDir, fqdn)
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
}

// Exists checks the live cert+key are both present.
func (c *Certbot) Exists(fqdn string) bool {
	cert, key := c.paths(fqdn)
	return fileExists(cert) && fileExists(key)
}

// Ensure runs certbot certonly --webroot for fqdn when the cert is absent.
func (c *Certbot) Ensure(ctx context.Context, fqdn string) error {
	if c.Exists(fqdn) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	args := []string{
		"certonly", "--webroot", "-w", c.Webroot,
		"-d", fqdn,
		"--non-interactive", "--agree-tos",
		"--keep-until-expiring",
	}
	if c.Email != "" {
		args = append(args, "-m", c.Email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &Error{Output: strings.TrimSpace(string(out)), Err: err}
	}
	return nil
}

// Error carries certbot's output for reporting on /status.
type Error struct {
	Output string
	Err    error
}

func (e *Error) Error() string {
	if e.Output != "" {
		return e.Output
	}
	return e.Err.Error()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
