// Package certbot obtains, inspects, and removes Let's Encrypt certificates for custom
// domains via the webroot HTTP-01 challenge.
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
	// Exists reports whether a usable cert+key already exist for fqdn — the
	// question a vhost render asks, since nginx needs the files themselves.
	Exists(fqdn string) bool
	// LineageExists reports whether certbot still tracks a renewal lineage for
	// fqdn, whether or not usable cert files remain — the question cleanup asks.
	LineageExists(fqdn string) bool
	// Ensure obtains (HTTP-01 webroot) a cert for fqdn if absent. It returns nil
	// once the cert exists on disk. Called only after the challenge vhost is live.
	Ensure(ctx context.Context, fqdn string) error
	// Delete drops fqdn's certificate and renewal lineage. Idempotent: an absent
	// lineage is success.
	Delete(ctx context.Context, fqdn string) error
}

// Certbot is the production Provider.
type Certbot struct {
	Bin        string
	Webroot    string
	LEDir      string // /etc/letsencrypt/live
	RenewalDir string // /etc/letsencrypt/renewal
	Email      string
	Timeout    time.Duration
}

// New returns a Certbot provider. The renewal directory is the live directory's
// sibling: certbot lays out live/, archive/, and renewal/ side by side under its
// config dir, so pointing the agent at a non-default live directory moves both. The
// path is cleaned first — a configured value with a trailing slash would otherwise
// put the renewal directory inside the live one.
func New(bin, webroot, leDir, email string, timeout time.Duration) *Certbot {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Certbot{
		Bin:        bin,
		Webroot:    webroot,
		LEDir:      leDir,
		RenewalDir: filepath.Join(filepath.Dir(filepath.Clean(leDir)), "renewal"),
		Email:      email,
		Timeout:    timeout,
	}
}

// paths returns the fullchain/privkey paths certbot writes for fqdn.
func (c *Certbot) paths(fqdn string) (cert, key string) {
	base := filepath.Join(c.LEDir, fqdn)
	return filepath.Join(base, "fullchain.pem"), filepath.Join(base, "privkey.pem")
}

// renewalConf returns the renewal configuration certbot writes for fqdn's lineage.
func (c *Certbot) renewalConf(fqdn string) string {
	return filepath.Join(c.RenewalDir, fqdn+".conf")
}

// Exists checks the live cert+key are both present.
func (c *Certbot) Exists(fqdn string) bool {
	cert, key := c.paths(fqdn)
	return fileExists(cert) && fileExists(key)
}

// LineageExists checks the renewal configuration, not the live cert files, because
// that file is what "certbot still knows about this lineage" actually means:
//
//   - `certbot renew` walks the renewal directory, so a renewal configuration left
//     behind is precisely what fails every renewal from then on;
//   - `certbot delete --cert-name` resolves the lineage through that same file and
//     errors out when it is missing, so it is also the only shape delete can clean.
//
// The two directories outlive one another in both directions. Deletion removes the
// renewal configuration first and the cert files after, so an interrupted delete
// leaves live files with no lineage; a hand-removed live directory leaves the
// reverse. Only the latter makes renewal noise, and only the latter is reclaimable
// — the former is inert and certbot has no way to touch it anyway.
func (c *Certbot) LineageExists(fqdn string) bool {
	return fileExists(c.renewalConf(fqdn))
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

// Delete removes fqdn's certificate and its renewal configuration. A lineage left
// behind after the domain stops pointing here fails every subsequent `certbot renew`,
// so the renewal timer sits permanently failed and a real renewal failure is no longer
// distinguishable from the noise. The LineageExists gate makes the call idempotent
// without depending on how certbot reports an unknown --cert-name.
func (c *Certbot) Delete(ctx context.Context, fqdn string) error {
	if !c.LineageExists(fqdn) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Bin, "delete", "--cert-name", fqdn, "--non-interactive")
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
