package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// ToolPins remembers the hash of each MCP tool definition the proxy has
// served, so a later change (a "rug pull") can be detected. It is persisted
// next to the blocklist and shared across sessions.
type ToolPins struct {
	Path  string
	mu    sync.Mutex
	Hash  map[string]string `json:"hashes"`
	dirty bool
}

// DefaultPinsPath is the pins file beside the blocklist.
func DefaultPinsPath() string {
	if p := os.Getenv("SAIFETY_PINS"); p != "" {
		return p
	}
	return filepath.Join(filepath.Dir(DefaultBlocklistPath()), "toolpins.json")
}

// LoadPins reads the pins file; a missing file yields an empty store.
func LoadPins(path string) (*ToolPins, error) {
	tp := &ToolPins{Path: path, Hash: map[string]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return tp, nil
	}
	if err != nil {
		return nil, err
	}
	return tp, json.Unmarshal(b, tp)
}

// Seen records key's hash and reports whether it was known and whether it
// changed. A first sighting is pinned and saved; a change keeps the ORIGINAL
// pin (so the tool keeps being flagged until a human re-accepts it by
// deleting the pin).
func (t *ToolPins) Seen(key, hash string) (known, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old, ok := t.Hash[key]
	if !ok {
		t.Hash[key] = hash
		t.dirty = true
		t.save()
		return false, false
	}
	return true, old != hash
}

func (t *ToolPins) save() {
	if !t.dirty {
		return
	}
	if err := os.MkdirAll(filepath.Dir(t.Path), 0o755); err != nil {
		return
	}
	if b, err := json.MarshalIndent(t, "", "  "); err == nil {
		_ = os.WriteFile(t.Path, b, 0o644)
		t.dirty = false
	}
}
