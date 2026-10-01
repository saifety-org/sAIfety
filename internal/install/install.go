// Package install performs the one-command takeover: it moves every MCP
// server out of a Claude client's config and into sAIfety's own config, then
// points the client at a single "saifety" server that proxies them all with
// scanning. After running it, the user works through the sanitizer with no
// further setup. uninstall restores the original from the backup.
//
// Supported clients: Claude Code (user scope, ~/.claude.json) and Claude
// Desktop (claude_desktop_config.json). Both keep MCP servers in a top-level
// "mcpServers" object, so one code path handles them.
package install

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// ProxyServerName is the single entry sAIfety leaves in the client config.
const ProxyServerName = "saifety"

// Target is a Claude client whose config we can rewrite.
type Target struct {
	Key        string // "claude-code" | "cursor" | ...
	Name       string // human label
	Path       string // config file path
	ServersKey string // top-level JSON key holding the servers map
}

// Targets returns the known clients for this OS with resolved paths.
func Targets() []Target {
	home, _ := os.UserHomeDir()
	var desktop string
	switch runtime.GOOS {
	case "darwin":
		desktop = filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		desktop = filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json")
	default:
		desktop = filepath.Join(configHome(home), "Claude", "claude_desktop_config.json")
	}
	return []Target{
		{Key: "claude-code", Name: "Claude Code", Path: filepath.Join(home, ".claude.json"), ServersKey: "mcpServers"},
		{Key: "claude-desktop", Name: "Claude Desktop", Path: desktop, ServersKey: "mcpServers"},
		{Key: "cursor", Name: "Cursor", Path: filepath.Join(home, ".cursor", "mcp.json"), ServersKey: "mcpServers"},
		{Key: "windsurf", Name: "Windsurf", Path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), ServersKey: "mcpServers"},
		{Key: "vscode", Name: "VS Code (user)", Path: vscodeUserMCP(home), ServersKey: "servers"},
	}
}

// vscodeUserMCP is the per-user MCP config for VS Code / the MCP extension.
func vscodeUserMCP(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Code", "User", "mcp.json")
	case "windows":
		return filepath.Join(os.Getenv("APPDATA"), "Code", "User", "mcp.json")
	default:
		return filepath.Join(configHome(home), "Code", "User", "mcp.json")
	}
}

func configHome(home string) string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return x
	}
	return filepath.Join(home, ".config")
}

// Find returns the target with the given key.
func Find(key string) (Target, bool) {
	for _, t := range Targets() {
		if t.Key == key {
			return t, true
		}
	}
	return Target{}, false
}

// Plan describes what an install would change, for -dry-run and reporting.
type Plan struct {
	Target     Target
	Moved      []string // stdio servers moved under the proxy
	LeftRemote []string // http/ws/sse servers left in place (proxy can't relay them yet)
	Backup     string
	Installed  bool // already pointing at saifety
}

// SaifetyConfig is the subset of saifety.json this package reads and writes.
// Unknown fields are preserved on write.
type SaifetyConfig struct {
	raw     map[string]json.RawMessage
	servers map[string]json.RawMessage
}

// Options controls a takeover.
type Options struct {
	Self          string // absolute path to the saifety binary
	SaifetyConfig string // path to saifety.json to write upstreams into
	DryRun        bool
	Out           io.Writer
}

// Install moves servers from target into saifety.json and rewrites target.
func Install(t Target, opts Options) (Plan, error) {
	p := Plan{Target: t}
	root, err := readJSON(t.Path)
	if err != nil {
		return p, err
	}
	key := t.ServersKey
	if key == "" {
		key = "mcpServers"
	}
	servers, err := decodeServers(root[key])
	if err != nil {
		return p, fmt.Errorf("%s: %s: %w", t.Path, key, err)
	}

	proxyEntry := proxyServer(opts.Self, opts.SaifetyConfig)
	toMove := map[string]json.RawMessage{}
	for name, spec := range servers {
		if name == ProxyServerName {
			continue
		}
		// The proxy relays every MCP transport (stdio, http, ws, sse), so
		// all servers move under it.
		toMove[name] = spec
		p.Moved = append(p.Moved, name)
	}
	sort.Strings(p.Moved)
	if len(p.Moved) == 0 {
		p.Installed = true // nothing to move (already done, or empty)
	}

	if opts.DryRun {
		fmt.Fprintf(opts.Out, "%s (%s)\n", t.Name, t.Path)
		if p.Installed {
			fmt.Fprintln(opts.Out, "  already installed, nothing to move")
			return p, nil
		}
		fmt.Fprintf(opts.Out, "  move %d server(s) into %s: %v\n", len(p.Moved), opts.SaifetyConfig, p.Moved)
		fmt.Fprintf(opts.Out, "  replace them with a single %q entry\n", ProxyServerName)
		fmt.Fprintf(opts.Out, "  backup: %s\n", t.Path+backupSuffix)
		return p, nil
	}
	if p.Installed {
		return p, nil
	}

	// 1. Move the servers into saifety.json (merge, never lose existing).
	if err := mergeIntoSaifety(opts.SaifetyConfig, toMove); err != nil {
		return p, err
	}
	// 2. Back up the client config once (don't clobber an earlier backup).
	if err := backupOnce(t.Path); err != nil {
		return p, err
	}
	p.Backup = t.Path + backupSuffix
	// 3. Replace the client's mcpServers with the single proxy entry.
	newServers := map[string]json.RawMessage{ProxyServerName: proxyEntry}
	sb, _ := json.Marshal(newServers)
	root[key] = sb
	if err := writeJSON(t.Path, root); err != nil {
		return p, err
	}
	return p, nil
}

// Uninstall restores the client config from its backup.
func Uninstall(t Target, opts Options) error {
	backup := t.Path + backupSuffix
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("no backup at %s; restore mcpServers manually from %s", backup, opts.SaifetyConfig)
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	if err := os.WriteFile(t.Path, data, 0o644); err != nil {
		return err
	}
	return os.Remove(backup)
}

func proxyServer(self, cfg string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"type":    "stdio",
		"command": self,
		"args":    []string{"proxy", "--config", cfg},
	})
	return b
}
