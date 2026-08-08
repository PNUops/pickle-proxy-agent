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
// FQDN's Exists to true, unless EnsureErr is set (simulates an issuance failure);
// Delete flips it back, unless DeleteErr is set.
//
// Cert files and renewal lineage are tracked separately, exactly as certbot keeps
// them in two directories: issuance creates both, deletion drops both, and
// StrandLineage reproduces the half-broken state where only the lineage is left.
type Certbot struct {
	mu        sync.Mutex
	Present   map[string]bool
	Lineage   map[string]bool
	EnsureErr error
	DeleteErr error
	Ensured   []string
	Deleted   []string
}

// NewCertbot returns an empty Certbot double.
func NewCertbot() *Certbot {
	return &Certbot{Present: map[string]bool{}, Lineage: map[string]bool{}}
}

// Exists reports whether a cert has been "issued" for fqdn.
func (f *Certbot) Exists(fqdn string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Present[fqdn]
}

// LineageExists reports whether a renewal lineage is still tracked for fqdn.
func (f *Certbot) LineageExists(fqdn string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Lineage[fqdn]
}

// StrandLineage drops fqdn's cert files while keeping its renewal lineage — the
// state a hand-removed live directory leaves behind.
func (f *Certbot) StrandLineage(fqdn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Present, fqdn)
	f.Lineage[fqdn] = true
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
	f.Lineage[fqdn] = true
	return nil
}

// Delete records the call and, on success, marks the cert absent.
func (f *Certbot) Delete(_ context.Context, fqdn string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Deleted = append(f.Deleted, fqdn)
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	delete(f.Present, fqdn)
	delete(f.Lineage, fqdn)
	return nil
}

// DeletedFQDNs returns a copy of the FQDNs Delete was called for.
func (f *Certbot) DeletedFQDNs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Deleted...)
}
