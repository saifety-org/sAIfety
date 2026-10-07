// Package stats keeps persistent counters of what sAIfety has detected, so
// the operator can review threat activity with `saifety statistics`. Counters
// are updated by every path that produces a verdict (scan, proxy, hooks) and
// stored in a small JSON file in the state directory.
package stats

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/saifety-org/sAIfety/internal/scan"
)

// Data is the persisted counter set.
type Data struct {
	Documents  int            `json:"documents"` // documents scanned
	Findings   int            `json:"findings"`  // total findings
	Blocked    int            `json:"blocked"`   // verdicts with action=block
	Sanitized  int            `json:"sanitized"` // verdicts with action=sanitize
	Warned     int            `json:"warned"`    // verdicts with action=warn
	ByCategory map[string]int `json:"byCategory"`
	ByLevel    map[string]int `json:"byLevel"`
	BySource   map[string]int `json:"bySource"`
	FirstSeen  time.Time      `json:"firstSeen"`
	LastSeen   time.Time      `json:"lastSeen"`
}

// Stats is a thread-safe, file-backed counter store. A nil *Stats is a valid
// no-op, so callers can hold one unconditionally.
type Stats struct {
	Path string
	mu   sync.Mutex
	data Data
}

// Scopes are the separate counter namespaces. scan is one-shot repository
// scanning; proxy and hook are the runtime paths.
var Scopes = []string{"scan", "proxy", "hook"}

// Dir is the directory holding per-scope stats files: $SAIFETY_STATS_DIR,
// else <state>/saifety.
func Dir() string {
	if p := os.Getenv("SAIFETY_STATS_DIR"); p != "" {
		return p
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "saifety")
}

// ScopePath is the stats file for one scope, e.g. stats-scan.json.
func ScopePath(scope string) string {
	return filepath.Join(Dir(), "stats-"+scope+".json")
}

// Load reads the counters; a missing file yields an empty store.
func Load(path string) (*Stats, error) {
	s := &Stats{Path: path, data: newData()}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	if s.data.ByCategory == nil {
		s.data = newData()
	}
	return s, nil
}

func newData() Data {
	return Data{ByCategory: map[string]int{}, ByLevel: map[string]int{}, BySource: map[string]int{}}
}

// Record folds one verdict into the counters and saves. Safe on a nil *Stats.
func (s *Stats) Record(v scan.Verdict) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.data.Documents++
	now := time.Now()
	if s.data.FirstSeen.IsZero() {
		s.data.FirstSeen = now
	}
	s.data.LastSeen = now
	if len(v.Findings) > 0 {
		s.data.ByLevel[v.Level.String()]++
		switch v.Action {
		case scan.ActionBlock:
			s.data.Blocked++
		case scan.ActionSanitize:
			s.data.Sanitized++
		case scan.ActionWarn:
			s.data.Warned++
		}
		if v.Source != "" {
			s.data.BySource[v.Source]++
		}
	}
	for _, f := range v.Findings {
		s.data.Findings++
		s.data.ByCategory[string(f.Category)]++
	}
	s.save()
	s.mu.Unlock()
}

// Snapshot returns a copy of the current data.
func (s *Stats) Snapshot() Data {
	if s == nil {
		return newData()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data
}

// Reset clears all counters and removes the file.
func (s *Stats) Reset() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = newData()
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Stats) save() {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return
	}
	if b, err := json.MarshalIndent(s.data, "", "  "); err == nil {
		_ = os.WriteFile(s.Path, b, 0o644)
	}
}

// SortedCounts returns the map as (key,count) pairs sorted by count desc.
func SortedCounts(m map[string]int) []KV {
	kv := make([]KV, 0, len(m))
	for k, v := range m {
		kv = append(kv, KV{k, v})
	}
	sort.Slice(kv, func(i, j int) bool {
		if kv[i].Count != kv[j].Count {
			return kv[i].Count > kv[j].Count
		}
		return kv[i].Key < kv[j].Key
	})
	return kv
}

// KV is a key/count pair.
type KV struct {
	Key   string
	Count int
}
