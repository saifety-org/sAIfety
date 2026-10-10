package policy

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

func TestBlocklistInterruptedWriterKeepsStateAndReleasesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	b := loadTestBlocklist(t, path)
	if err := b.Block("old", "committed"); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestBlocklistInterruptedWriterHelper$")
	cmd.Env = append(os.Environ(), "SAIFETY_TEST_CRASH_PATH="+path)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	waitTestFile(t, path+".writing")
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected killed writer to fail")
	}
	if blocked, err := b.Check("old"); err != nil || !blocked {
		t.Fatalf("interrupted writer lost previous state or retained lock: %v", err)
	}
	if err := b.Block("new", "after crash"); err != nil {
		t.Fatal(err)
	}
	if !b.Blocked("old") || !b.Blocked("new") {
		t.Fatal("recovery after interrupted writer failed")
	}
}

func TestBlocklistInterruptedWriterHelper(t *testing.T) {
	path := os.Getenv("SAIFETY_TEST_CRASH_PATH")
	if path == "" {
		return
	}
	b := loadTestBlocklist(t, path)
	err := b.withFileLock(func() error {
		return writeBlocklist(path, func(f *os.File) error {
			if _, err := f.WriteString(`{"entries":`); err != nil {
				return err
			}
			if err := os.WriteFile(path+".writing", nil, 0o600); err != nil {
				return err
			}
			for {
				time.Sleep(time.Hour)
			}
		})
	})
	t.Fatalf("interrupted writer unexpectedly returned: %v", err)
}

func TestBlocklistManualUnblockAndIndependentSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, b := loadTestBlocklist(t, path), loadTestBlocklist(t, path)
	if err := a.Block("old", "fixture"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	delete(snapshot, "old")
	if !a.Blocked("old") {
		t.Fatal("caller changed internal state through snapshot")
	}
	if err := os.WriteFile(path, []byte(`{"entries":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if a.Blocked("old") {
		t.Fatal("running reader did not observe manual edit")
	}
	if err := b.Block("new", "fixture"); err != nil {
		t.Fatal(err)
	}
	if a.Blocked("old") {
		t.Fatal("stale writer resurrected manually removed source")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if a.Blocked("new") {
		t.Fatal("running reader did not observe manual deletion")
	}
	if err := b.Block("after-delete", "fixture"); err != nil {
		t.Fatal(err)
	}
	if a.Blocked("new") || !a.Blocked("after-delete") {
		t.Fatal("delete was undone by stale state")
	}
}

func TestBlocklistCorruptStateIsNotOverwritten(t *testing.T) {
	for _, raw := range []string{`{`, `null`, `{"entries":[]}`} {
		t.Run(raw, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			b := loadTestBlocklist(t, path)
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := b.Check("unknown"); err == nil {
				t.Fatal("corrupt state allowed access")
			}
			if !b.Blocked("unknown") {
				t.Fatal("conservative access check failed open")
			}
			if err := b.Block("pending", "fixture"); err == nil {
				t.Fatal("write silently replaced corrupt state")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != raw {
				t.Fatal("corrupt file was overwritten")
			}
			if err := os.WriteFile(path, []byte(`{"entries":{}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if !b.Blocked("pending") {
				t.Fatal("failed block was lost in current process")
			}
			if err := b.Block("retry", "fixture"); err != nil {
				t.Fatal(err)
			}
			fresh := loadTestBlocklist(t, path)
			if !fresh.Blocked("pending") || !fresh.Blocked("retry") {
				t.Fatal("pending writes were not retried")
			}
		})
	}
}

func TestBlocklistLockFailureAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	b := loadTestBlocklist(t, path)
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Check("unknown"); err == nil {
		t.Fatal("lock failure allowed unchecked access")
	}
	if err := b.Block("pending", "fixture"); err == nil {
		t.Fatal("lock failure was ignored")
	}
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if !b.Blocked("pending") {
		t.Fatal("block lost after lock recovery")
	}
	if err := b.Block("retry", "fixture"); err != nil {
		t.Fatal(err)
	}
}

func TestBlocklistLockTimeoutAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	b := loadTestBlocklist(t, path)
	lock := flock.New(path + ".lock")
	if err := lock.Lock(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if _, err := b.Check("unknown"); err == nil {
		t.Fatal("lock contention did not time out")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if blocked, err := b.Check("unknown"); blocked || err != nil {
		t.Fatalf("lock did not recover: %v", err)
	}
}

func TestBlocklistLegacyPathCannotRedirectWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	// A legacy Path field must not redirect persistence to another file.
	legacy, err := json.Marshal(map[string]any{"Path": filepath.Join(dir, "redirected.json"), "entries": map[string]any{"legacy": map[string]string{"reason": "fixture", "at": "2026-10-10T00:00:00Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	b := loadTestBlocklist(t, path)
	if err := b.Block("new", "fixture"); err != nil {
		t.Fatal(err)
	}
	fresh := loadTestBlocklist(t, path)
	if !fresh.Blocked("legacy") || !fresh.Blocked("new") {
		t.Fatal("legacy state format was not preserved")
	}
	if _, err := os.Stat(filepath.Join(dir, "redirected.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy Path metadata was used")
	}
}

func TestBlocklistFailedAtomicWriteKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	old := `{"entries":{"old":{"reason":"fixture"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("simulated disk failure")
	err := writeBlocklist(path, func(f *os.File) error {
		if _, err := f.WriteString(`{"entries":`); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("write error lost: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != old {
		t.Fatal("failed write replaced previous complete JSON")
	}
	temps, err := filepath.Glob(filepath.Join(dir, ".blocklist-*"))
	if err != nil || len(temps) != 0 {
		t.Fatal("failed write left temporary files")
	}
	if err := writeBlocklist(path, func(f *os.File) error { _, err := f.WriteString(`{"entries":{}}`); return err }); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("state permissions must be owner-only")
		}
	}
}
