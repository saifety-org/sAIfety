package policy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func loadTestBlocklist(t *testing.T, path string) *Blocklist {
	t.Helper()
	b, err := LoadBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBlocklistPreservesUpdatesFromStaleInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	a, b := loadTestBlocklist(t, path), loadTestBlocklist(t, path)
	if err := a.Block("a", "first process"); err != nil {
		t.Fatal(err)
	}
	if err := b.Block("b", "stale second process"); err != nil {
		t.Fatal(err)
	}
	latest := loadTestBlocklist(t, path)
	if !latest.Blocked("a") || !latest.Blocked("b") {
		t.Fatal("a stale writer lost another writer's block")
	}
	if !a.Blocked("b") {
		t.Fatal("running reader did not observe another process's block")
	}
}

func TestBlocklistConcurrentReadersAndWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	b := loadTestBlocklist(t, path)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := 0; n < 12; n++ {
				source := fmt.Sprintf("source-%d-%d", worker, n)
				if worker < 4 {
					if err := b.Block(source, "concurrent"); err != nil {
						t.Error(err)
						return
					}
				} else {
					_ = b.Blocked("source-0-0")
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	latest := loadTestBlocklist(t, path)
	for worker := 0; worker < 4; worker++ {
		for n := 0; n < 12; n++ {
			if !latest.Blocked(fmt.Sprintf("source-%d-%d", worker, n)) {
				t.Fatal("concurrent update lost")
			}
		}
	}
}

func TestBlocklistMultipleProcesses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	var cmds []*exec.Cmd
	for worker := 0; worker < 4; worker++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBlocklistProcessHelper$")
		cmd.Env = append(os.Environ(), "SAIFETY_TEST_BLOCKLIST="+path, "SAIFETY_TEST_WORKER="+strconv.Itoa(worker))
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
		t.Cleanup(func() { _ = cmd.Process.Kill() })
	}
	for worker := 0; worker < 4; worker++ {
		waitTestFile(t, path+".ready-"+strconv.Itoa(worker))
	}
	if err := os.WriteFile(path+".start", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	b := loadTestBlocklist(t, path)
	for worker := 0; worker < 4; worker++ {
		for n := 0; n < 8; n++ {
			if !b.Blocked(fmt.Sprintf("process-%d-%d", worker, n)) {
				t.Fatal("interprocess update lost")
			}
		}
	}
}

func TestBlocklistProcessHelper(t *testing.T) {
	path := os.Getenv("SAIFETY_TEST_BLOCKLIST")
	if path == "" {
		return
	}
	worker := os.Getenv("SAIFETY_TEST_WORKER")
	b := loadTestBlocklist(t, path)
	if err := os.WriteFile(path+".ready-"+worker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitTestFile(t, path+".start")
	for n := 0; n < 8; n++ {
		if err := b.Block(fmt.Sprintf("process-%s-%d", worker, n), "process fixture"); err != nil {
			t.Fatal(err)
		}
	}
}

func waitTestFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for fixture %s", path)
}
