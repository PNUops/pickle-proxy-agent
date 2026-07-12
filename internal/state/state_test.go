package state

import (
	"path/filepath"
	"testing"

	"github.com/pnuops/pickle-proxy-agent/internal/model"
)

func TestRecordAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, known := s.Generation("a.com"); known {
		t.Fatal("fresh store should not know a.com")
	}
	if err := s.Record("a.com", Entry{Generation: 5, Present: true}); err != nil {
		t.Fatal(err)
	}

	// Reload from disk: the generation must survive a restart.
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	gen, known := s2.Generation("a.com")
	if !known || gen != 5 {
		t.Fatalf("after reload gen=%d known=%v, want 5,true", gen, known)
	}
}

func TestAbsentKeepsGeneration(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "state.json"))
	// ABSENT records present=false but must keep the generation so a later stale
	// PRESENT (gen ≤ this) is still rejected.
	_ = s.Record("gone.com", Entry{Generation: 9, Present: false})
	gen, known := s.Generation("gone.com")
	if !known || gen != 9 {
		t.Fatalf("ABSENT should keep gen 9, got %d known=%v", gen, known)
	}
}

func TestSnapshotGenerationAndReplaceAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Load(path)
	if s.SnapshotGeneration() != 0 {
		t.Fatal("fresh snapshot gen should be 0")
	}
	_ = s.ReplaceAll(map[string]Entry{"a.com": {Generation: 1, Present: true}}, 100)
	if s.SnapshotGeneration() != 100 {
		t.Fatalf("snapshot gen = %d, want 100", s.SnapshotGeneration())
	}
	// ReplaceAll is authoritative: entries not in the new set are gone.
	if _, known := s.Generation("old.com"); known {
		t.Fatal("ReplaceAll should have dropped unknown entries")
	}
	s2, _ := Load(path)
	if s2.SnapshotGeneration() != 100 {
		t.Fatalf("snapshot gen not persisted: %d", s2.SnapshotGeneration())
	}
}

func TestSetCert(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "state.json"))
	_ = s.Record("shop.com", Entry{Generation: 1, Present: true})
	_ = s.SetCert("shop.com", model.CertFailed, "boom")
	e, _ := s.Get("shop.com")
	if e.CertState != model.CertFailed || e.CertError != "boom" {
		t.Fatalf("cert state = %+v", e)
	}
	if e.Generation != 1 || !e.Present {
		t.Fatalf("SetCert must preserve generation/present: %+v", e)
	}
}
