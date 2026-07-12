// Package nginx wraps the two nginx operations the agent performs: validating the
// on-disk config (`nginx -t`) and gracefully reloading (`nginx -s reload`).
//
// It is an interface so the manager's atomic apply/rollback logic can be tested
// against a fake without a real nginx. `nginx -t` validates the *entire* on-disk
// config (server blocks in pickle.d only make sense inside the base http{} context),
// so the agent's discipline is: mutate the include dir, run Test, and roll the file
// back if Test fails — Reload is issued only after Test passes, so the running nginx
// is never exposed to a bad candidate.
package nginx

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Nginx is the subset of nginx the agent drives.
type Nginx interface {
	// Test runs a full config validation. On failure it returns the combined
	// stderr/stdout (surfaced verbatim to pickle-api) and a non-nil error.
	Test(ctx context.Context) (output string, err error)
	// Reload gracefully reloads workers.
	Reload(ctx context.Context) error
}

// Exec is the production Nginx driven by a real binary.
type Exec struct {
	Bin     string
	Timeout time.Duration
}

// New returns an Exec bound to the given binary.
func New(bin string, timeout time.Duration) *Exec {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Exec{Bin: bin, Timeout: timeout}
}

func (e *Exec) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.Bin, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Test runs `nginx -t`.
func (e *Exec) Test(ctx context.Context) (string, error) {
	return e.run(ctx, "-t")
}

// Reload runs `nginx -s reload`.
func (e *Exec) Reload(ctx context.Context) error {
	_, err := e.run(ctx, "-s", "reload")
	return err
}
