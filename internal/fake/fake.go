// Package fake provides in-memory nginx and certbot doubles so the agent's logic can
// be exercised without a real nginx or Let's Encrypt. It is imported only by tests
// (never by cmd/proxy-agent), so it does not ship in the daemon binary.
package fake

import (
	"context"
	"errors"
	"sync"
)

// Nginx is a controllable nginx.Nginx double.
type Nginx struct {
	mu       sync.Mutex
	FailTest bool   // when true, Test returns an error (simulates `nginx -t` failure)
	TestMsg  string // stderr returned on failure
	Tests    int
	Reloads  int
}

// Test records the call and fails when FailTest is set.
func (f *Nginx) Test(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Tests++
	if f.FailTest {
		msg := f.TestMsg
		if msg == "" {
			msg = "nginx: [emerg] test failed"
		}
		return msg, errors.New("nginx -t failed")
	}
	return "nginx: configuration file test is successful", nil
}

// Reload records the call.
func (f *Nginx) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Reloads++
	return nil
}

// Counts returns the number of Test and Reload calls seen.
func (f *Nginx) Counts() (tests, reloads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Tests, f.Reloads
}

// Certbot is a certbot.Provider double. Ensure "issues" a cert by flipping the
// FQDN's Exists to true, unless EnsureErr is set (simulates an issuance failure).
type Certbot struct {
	mu        sync.Mutex
	Present   map[string]bool
	EnsureErr error
	Ensured   []string
}

// NewCertbot returns an empty Certbot double.
func NewCertbot() *Certbot { return &Certbot{Present: map[string]bool{}} }

// Exists reports whether a cert has been "issued" for fqdn.
func (f *Certbot) Exists(fqdn string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Present[fqdn]
}

// Ensure records the call and, on success, marks the cert present.
func (f *Certbot) Ensure(_ context.Context, fqdn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Ensured = append(f.Ensured, fqdn)
	if f.EnsureErr != nil {
		return f.EnsureErr
	}
	f.Present[fqdn] = true
	return nil
}
