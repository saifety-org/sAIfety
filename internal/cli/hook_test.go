package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreToolHookDeniesWhenInitialBlocklistLoadFails(t *testing.T) {
	dir := t.TempDir()
	state, cfg := filepath.Join(dir, "state.json"), filepath.Join(dir, "config.json")
	if err := os.WriteFile(state, []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAIFETY_STATE", state)
	var stdout, stderr bytes.Buffer
	code := runHook(context.Background(), []string{"-config", cfg, "pre-tool-use"}, strings.NewReader(`{}`), &stdout, &stderr)
	if code != ExitClean {
		t.Fatalf("a hook error would not enforce deny: code=%d, %s", code, stderr.String())
	}
	var output struct {
		HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.HookSpecificOutput["permissionDecision"] != "deny" || !strings.Contains(stderr.String(), "state:") {
		t.Fatalf("state failure did not produce explicit deny: %s / %s", stdout.String(), stderr.String())
	}
}
