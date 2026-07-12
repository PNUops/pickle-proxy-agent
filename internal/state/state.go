// Package state persists the last-applied generation per FQDN (and cert state) so a
// restart cannot forget what it applied and thereby accept a stale request that would
// resurrect an old vhost onto a reused IP. It is a small JSON file written atomically.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

// Entry is one FQDN's persisted record.
type Entry struct {
	Generation int64           `json:"generation"`
	Present    bool            `json:"present"`
	AppliedAt  time.Time       `json:"appliedAt"`
	CertState  model.CertState `json:"certState,omitempty"`
	CertError  string          `json:"certError,omitempty"`
	CertAt     time.Time       `json:"certAt,omitempty"`
}

// Store is the in-memory generation map backed by a JSON file. All methods are safe
// for concurrent use; the manager still serializes mutations, but /status reads
// concurrently with an in-flight apply.
type Store struct {
	mu          sync.RWMutex
	path        string
	Entries     map[string]Entry
	snapshotGen int64 // last accepted /sync-all snapshotGeneration (monotonic guard)
}

type persisted struct {
	SnapshotGeneration int64            `json:"snapshotGeneration"`
	Entries            map[string]Entry `json:"entries"`
}

// Load reads the store from path, creating an empty one if the file is absent.
func Load(path string) (*Store, error) {
	s := &Store{path: path, Entries: map[string]Entry{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if p.Entries != nil {
		s.Entries = p.Entries
	}
	s.snapshotGen = p.SnapshotGeneration
	return s, nil
}

// Generation returns the applied generation for an FQDN and whether it is known.
func (s *Store) Generation(fqdn string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.Entries[fqdn]
	return e.Generation, ok
}

// SnapshotGeneration returns the last accepted /sync-all snapshotGeneration.
func (s *Store) SnapshotGeneration() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotGen
}

// Get returns a copy of an FQDN's entry.
func (s *Store) Get(fqdn string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.Entries[fqdn]
	return e, ok
}

// Record sets an FQDN's entry and persists. present=false keeps the generation
// record after an ABSENT apply — that record is what rejects a later stale PRESENT.
func (s *Store) Record(fqdn string, e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Entries[fqdn] = e
	return s.persistLocked()
}

// SetCert updates only the certificate fields for an FQDN.
func (s *Store) SetCert(fqdn string, cs model.CertState, certErr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.Entries[fqdn]
	e.CertState = cs
	e.CertError = certErr
	e.CertAt = time.Now()
	s.Entries[fqdn] = e
	return s.persistLocked()
}

// ReplaceAll atomically replaces the full entry set (used by /sync-all after a
// successful swap) and advances the snapshot generation.
func (s *Store) ReplaceAll(entries map[string]Entry, snapshotGen int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Entries = entries
	s.snapshotGen = snapshotGen
	return s.persistLocked()
}

// Snapshot returns a copy of all entries for /status.
func (s *Store) Snapshot() map[string]Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Entry, len(s.Entries))
	for k, v := range s.Entries {
		out[k] = v
	}
	return out
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(persisted{SnapshotGeneration: s.snapshotGen, Entries: s.Entries}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
