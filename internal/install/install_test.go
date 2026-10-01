package install

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func servers(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	root, err := readJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeServers(root["mcpServers"])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallMovesStdioLeavesRemoteAndRestores(t *testing.T) {
	dir := t.TempDir()
	client := filepath.Join(dir, "claude.json")
	saifety := filepath.Join(dir, "saifety.json")
	write(t, client, `{
	  "numStartups": 7,
	  "mcpServers": {
	    "github": {"type":"stdio","command":"npx","args":["-y","srv"],"env":{"K":"v"}},
	    "grafana": {"command":"mcp-grafana"},
	    "remote": {"type":"http","url":"https://x.example/mcp"}
	  },
	  "preferences": {"theme":"dark"}
	}`)
	tgt := Target{Key: "test", Name: "Test", Path: client}
	opts := Options{Self: "/usr/local/bin/saifety", SaifetyConfig: saifety, Out: &bytes.Buffer{}}

	p, err := Install(tgt, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Moved; len(got) != 3 || got[0] != "github" || got[1] != "grafana" || got[2] != "remote" {
		t.Fatalf("moved = %v, want [github grafana remote]", got)
	}

	// Client now has only the proxy entry; all servers moved under it.
	cs := servers(t, client)
	if len(cs) != 1 {
		t.Fatalf("client servers = %d, want 1", len(cs))
	}
	if _, ok := cs[ProxyServerName]; !ok {
		t.Fatal("proxy entry missing from client")
	}
	// Proxy entry points at saifety proxy.
	var pe struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	_ = json.Unmarshal(cs[ProxyServerName], &pe)
	if pe.Command != opts.Self || len(pe.Args) < 2 || pe.Args[0] != "proxy" {
		t.Fatalf("bad proxy entry: %+v", pe)
	}

	// Unrelated keys preserved.
	root, _ := readJSON(client)
	if _, ok := root["preferences"]; !ok {
		t.Fatal("preferences key lost")
	}
	if _, ok := root["numStartups"]; !ok {
		t.Fatal("numStartups key lost")
	}

	// saifety.json received the two stdio servers, not the remote or proxy.
	ss := servers(t, saifety)
	if len(ss) != 3 || ss["github"] == nil || ss["grafana"] == nil || ss["remote"] == nil {
		t.Fatalf("saifety servers = %v", keys(ss))
	}
	if ss[ProxyServerName] != nil {
		t.Fatal("saifety.json must not hold the proxy entry")
	}

	// Backup exists.
	if _, err := os.Stat(client + backupSuffix); err != nil {
		t.Fatal("backup not created")
	}

	// Idempotent: a second install moves nothing.
	p2, err := Install(tgt, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Moved) != 0 {
		t.Fatalf("second install moved %v, want none", p2.Moved)
	}

	// Uninstall restores the original exactly.
	if err := Uninstall(tgt, opts); err != nil {
		t.Fatal(err)
	}
	restored := servers(t, client)
	if len(restored) != 3 || restored["github"] == nil || restored["remote"] == nil {
		t.Fatalf("restore incomplete: %v", keys(restored))
	}
	if _, err := os.Stat(client + backupSuffix); err == nil {
		t.Fatal("backup should be removed after uninstall")
	}
}

func TestInstallEmptyClient(t *testing.T) {
	dir := t.TempDir()
	client := filepath.Join(dir, "claude_desktop_config.json")
	write(t, client, `{"mcpServers":{}}`)
	tgt := Target{Key: "d", Name: "Desktop", Path: client}
	p, err := Install(tgt, Options{Self: "/bin/saifety", SaifetyConfig: filepath.Join(dir, "s.json"), Out: &bytes.Buffer{}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Installed || len(p.Moved) != 0 {
		t.Fatalf("empty client should be a no-op, got %+v", p)
	}
}

func keys(m map[string]json.RawMessage) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}

func TestInstallVSCodeServersKey(t *testing.T) {
	dir := t.TempDir()
	client := filepath.Join(dir, "mcp.json")
	saifety := filepath.Join(dir, "saifety.json")
	write(t, client, `{"servers":{"local":{"type":"stdio","command":"x","args":[]}}}`)
	tgt := Target{Key: "vscode", Name: "VS Code", Path: client, ServersKey: "servers"}
	opts := Options{Self: "/bin/saifety", SaifetyConfig: saifety, Out: nil}
	// Out nil is fine for non-dry-run.
	if _, err := Install(tgt, opts); err != nil {
		t.Fatal(err)
	}
	root, _ := readJSON(client)
	m, _ := decodeServers(root["servers"])
	if len(m) != 1 || m[ProxyServerName] == nil {
		t.Fatalf("vscode servers should hold only the proxy: %v", keys(m))
	}
	if root["mcpServers"] != nil {
		t.Fatal("must not create mcpServers for a servers-key client")
	}
}
