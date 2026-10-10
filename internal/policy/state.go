package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

// Blocklist persists sources that reached the critical level. The proxy and
// the hook adapter share it so a block made in one place holds in the other.
// Unblocking is a manual user action: edit or delete the file.
type Blocklist struct {
	mu      sync.Mutex
	path    string
	entries map[string]BlockEntry
	// Failed writes remain blocked in this process until a retry succeeds.
	pending map[string]BlockEntry
}

type blocklistState struct {
	Entries map[string]BlockEntry `json:"entries"`
}

const blocklistLockTimeout = 2 * time.Second

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
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Aliases of an existing file (or its parent directory) share one lock.
	canonical, err := filepath.EvalSymlinks(path)
	if errors.Is(err, os.ErrNotExist) {
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
		if parentErr != nil {
			return nil, parentErr
		}
		canonical = filepath.Join(parent, filepath.Base(path))
	} else if err != nil {
		return nil, err
	}
	bl := &Blocklist{path: canonical, entries: map[string]BlockEntry{}, pending: map[string]BlockEntry{}}
	_, err = bl.Snapshot()
	return bl, err
}

// Blocked is the conservative convenience form of Check: an unreadable state
// denies access. Runtime adapters use Check to report the error explicitly.
func (b *Blocklist) Blocked(source string) bool {
	blocked, err := b.Check(source)
	return blocked || err != nil
}

// Check refreshes the persisted state so running proxies see hook updates and
// manual unblocks without a restart.
func (b *Blocklist) Check(source string) (bool, error) {
	entries, err := b.Snapshot()
	if err != nil {
		return false, err
	}
	_, blocked := entries[source]
	return blocked, nil
}

// Snapshot returns an independent copy; callers never share the mutable map.
func (b *Blocklist) Snapshot() (map[string]BlockEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.withFileLock(func() error {
		entries, err := readBlocklist(b.path)
		if err != nil {
			return err
		}
		b.entries = entries
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b.mergedEntries(), nil
}

// Block serializes read/merge/replace across instances and processes. It never
// writes a stale snapshot over newer updates or resurrects a manual unblock.
func (b *Blocklist) Block(source, reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending[source] = BlockEntry{Reason: reason, At: time.Now()}
	return b.withFileLock(func() error {
		entries, err := readBlocklist(b.path)
		if err != nil {
			return err // Never overwrite a corrupt or unreadable file.
		}
		b.entries = entries
		merged := b.mergedEntries()
		err = writeBlocklist(b.path, func(f *os.File) error {
			encoder := json.NewEncoder(f)
			encoder.SetIndent("", "  ")
			return encoder.Encode(blocklistState{Entries: merged})
		})
		if err == nil {
			b.entries = merged
			clear(b.pending)
		}
		return err
	})
}

func (b *Blocklist) mergedEntries() map[string]BlockEntry {
	merged := make(map[string]BlockEntry, len(b.entries)+len(b.pending))
	for source, entry := range b.entries {
		merged[source] = entry
	}
	for source, entry := range b.pending {
		merged[source] = entry
	}
	return merged
}

func (b *Blocklist) withFileLock(fn func() error) (err error) {
	lock := flock.New(b.path+".lock", flock.SetPermissions(0o600), flock.SetFlag(os.O_CREATE|os.O_RDWR))
	defer func() { err = errors.Join(err, lock.Close()) }()
	ctx, cancel := context.WithTimeout(context.Background(), blocklistLockTimeout)
	defer cancel()
	locked, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return fmt.Errorf("blocklist lock: %w", err)
	}
	if !locked {
		return fmt.Errorf("blocklist lock unavailable")
	}
	return fn()
}

func readBlocklist(path string) (map[string]BlockEntry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]BlockEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read blocklist: %w", err)
	}
	var state *blocklistState
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("decode blocklist: %w", err)
	}
	if state == nil {
		return nil, fmt.Errorf("blocklist must be a JSON object")
	}
	if state.Entries == nil {
		state.Entries = map[string]BlockEntry{}
	}
	// Legacy "Path" metadata is ignored; only the configured path is writable.
	return state.Entries, nil
}

// writeBlocklist replaces the file only after the complete temporary file is
// flushed and closed. The caller holds the stable sidecar lock throughout.
func writeBlocklist(path string, write func(*os.File) error) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".blocklist-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err = write(f); err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncBlocklistDirectory(filepath.Dir(path))
}
