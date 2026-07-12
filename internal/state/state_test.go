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
	s2, _ := Load(path)
	if s2.SnapshotGeneration() != 100 {
		t.Fatalf("snapshot gen not persisted: %d", s2.SnapshotGeneration())
	}
}

func TestReplaceAllKeepsPrunedGenerationTombstone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Load(path)
	_ = s.Record("pruned.com", Entry{Generation: 7, Present: true})
	_ = s.Record("kept.com", Entry{Generation: 2, Present: true})

	// pruned.com is absent from the sync-all set: its generation must survive as a
	// present=false tombstone so a later stale PRESENT is still rejected.
	_ = s.ReplaceAll(map[string]Entry{"kept.com": {Generation: 3, Present: true}}, 100)
	e, known := s.Get("pruned.com")
	if !known || e.Generation != 7 || e.Present {
		t.Fatalf("tombstone = %+v known=%v, want gen=7 present=false", e, known)
	}
	if gen, _ := s.Generation("kept.com"); gen != 3 {
		t.Fatalf("kept.com gen = %d, want 3", gen)
	}
	// The tombstone survives a restart.
	s2, _ := Load(path)
	if gen, known := s2.Generation("pruned.com"); !known || gen != 7 {
		t.Fatalf("tombstone not persisted: gen=%d known=%v", gen, known)
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
