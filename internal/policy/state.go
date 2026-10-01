package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Blocklist persists sources that reached the critical level. The proxy and
// the hook adapter share it so a block made in one place holds in the other.
// Unblocking is a manual user action: edit or delete the file.
type Blocklist struct {
	Path    string
	Entries map[string]BlockEntry `json:"entries"`
}

// BlockEntry records why and when a source was blocked.
type BlockEntry struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// DefaultBlocklistPath is $XDG_STATE_HOME/saifety/blocklist.json or the
// equivalent under the home directory.
func DefaultBlocklistPath() string {
	if p := os.Getenv("SAIFETY_STATE"); p != "" {
		return p
	}
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "saifety", "blocklist.json")
}

// LoadBlocklist reads the file; a missing file is an empty list.
func LoadBlocklist(path string) (*Blocklist, error) {
	bl := &Blocklist{Path: path, Entries: map[string]BlockEntry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return bl, nil
	}
	if err != nil {
		return nil, err
	}
	return bl, json.Unmarshal(b, bl)
}

// Blocked reports whether source is blocked.
func (b *Blocklist) Blocked(source string) bool {
	_, ok := b.Entries[source]
	return ok
}

// Block adds source and saves the file.
func (b *Blocklist) Block(source, reason string) error {
	b.Entries[source] = BlockEntry{Reason: reason, At: time.Now()}
	if err := os.MkdirAll(filepath.Dir(b.Path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.Path, data, 0o644)
}
