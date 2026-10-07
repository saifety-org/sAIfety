package stats

import (
	"path/filepath"
	"testing"

	"github.com/saifety-org/sAIfety/internal/scan"
)

func TestRecordAndSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Record(scan.Verdict{Source: "a", Level: scan.LevelCritical, Action: scan.ActionBlock,
		Findings: []scan.Finding{{Category: scan.CatExfiltration}, {Category: scan.CatInstructionOverride}}})
	s.Record(scan.Verdict{Source: "b", Level: scan.LevelBase, Action: scan.ActionWarn,
		Findings: []scan.Finding{{Category: scan.CatPII}}})
	s.Record(scan.Verdict{Source: "c"}) // clean, no findings

	// Reload from disk to confirm persistence.
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d := s2.Snapshot()
	if d.Documents != 3 {
		t.Errorf("documents = %d, want 3", d.Documents)
	}
	if d.Findings != 3 {
		t.Errorf("findings = %d, want 3", d.Findings)
	}
	if d.Blocked != 1 || d.Warned != 1 {
		t.Errorf("actions blocked=%d warned=%d", d.Blocked, d.Warned)
	}
	if d.ByCategory["exfiltration"] != 1 || d.ByCategory["pii"] != 1 {
		t.Errorf("byCategory = %v", d.ByCategory)
	}
	if d.ByLevel["critical"] != 1 || d.ByLevel["base"] != 1 {
		t.Errorf("byLevel = %v", d.ByLevel)
	}
}

func TestNilStatsNoOp(t *testing.T) {
	var s *Stats
	s.Record(scan.Verdict{Findings: []scan.Finding{{Category: scan.CatPII}}}) // must not panic
	if d := s.Snapshot(); d.Documents != 0 {
		t.Fatal("nil stats should be empty")
	}
}

func TestReset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	s, _ := Load(path)
	s.Record(scan.Verdict{Source: "a", Findings: []scan.Finding{{Category: scan.CatPII}}})
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().Documents != 0 {
		t.Fatal("reset did not clear counters")
	}
}
