// Package launch prepares a safe Claude Code session: project instruction
// loading is switched off, sAIfety hooks are installed, and the only MCP
// server is the sAIfety proxy. Nothing is written into the project or the
// user's settings; everything goes to a temporary directory.
package launch

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Plan describes the generated session.
type Plan struct {
	Dir          string // project directory
	SelfPath     string // path to the saifety binary
	ConfigPath   string // saifety.json with mcpServers
	ClaudeBinary string
	ExtraArgs    []string
}

// Files are the generated config paths.
type Files struct {
	TempDir  string
	Settings string
	MCP      string
}

// Prepare writes the settings and MCP config files.
func Prepare(p Plan) (Files, error) {
	tmp, err := os.MkdirTemp("", "saifety-")
	if err != nil {
		return Files{}, err
	}
	abs, _ := filepath.Abs(p.Dir)
	cfgAbs, _ := filepath.Abs(p.ConfigPath)
	hook := func(event string) map[string]any {
		// The hook command is run by a shell, so paths are quoted (macOS
		// config dir is "~/Library/Application Support/...").
		cmd := shellQuote(p.SelfPath) + " hook -config " + shellQuote(cfgAbs) + " " + event
		return map[string]any{"type": "command", "command": cmd, "timeout": 60}
	}
	settings := map[string]any{
		// Штатная загрузка CLAUDE.md выключена: файл подаёт SessionStart-хук
		// после проверки. Управляется только из user/--settings, проект
		// не может это переопределить.
		"pluginConfigs": map[string]any{
			"agents-md@builtin": map[string]any{"options": map[string]any{"instructionFiles": "managed-only"}},
		},
		// managed-only не отключает ленивую загрузку вложенных CLAUDE.md.
		"claudeMdExcludes": []string{
			filepath.Join(abs, "**", "CLAUDE.md"),
			filepath.Join(abs, "**", "CLAUDE.local.md"),
			filepath.Join(abs, "**", ".claude", "rules", "**"),
		},
		"hooks": map[string]any{
			"SessionStart": []map[string]any{{"hooks": []map[string]any{hook("session-start")}}},
			"PreToolUse":   []map[string]any{{"matcher": "Read|Glob|Grep|Bash|WebFetch|mcp__.*", "hooks": []map[string]any{hook("pre-tool-use")}}},
			"PostToolUse":  []map[string]any{{"matcher": "Read|Bash|WebFetch|WebSearch|mcp__.*", "hooks": []map[string]any{hook("post-tool-use")}}},
		},
	}
	mcpCfg := map[string]any{
		"mcpServers": map[string]any{
			"saifety": map[string]any{"command": p.SelfPath, "args": []string{"proxy", "--config", cfgAbs}},
		},
	}
	f := Files{TempDir: tmp, Settings: filepath.Join(tmp, "settings.json"), MCP: filepath.Join(tmp, "mcp.json")}
	if err := writeJSON(f.Settings, settings); err != nil {
		return f, err
	}
	if err := writeJSON(f.MCP, mcpCfg); err != nil {
		return f, err
	}
	return f, nil
}

// Command builds the claude invocation.
func Command(p Plan, f Files) *exec.Cmd {
	bin := p.ClaudeBinary
	if bin == "" {
		bin = "claude"
	}
	args := []string{"--settings", f.Settings, "--mcp-config", f.MCP, "--strict-mcp-config"}
	args = append(args, p.ExtraArgs...)
	cmd := exec.Command(bin, args...)
	cmd.Dir = p.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd
}

// shellQuote wraps s in single quotes, escaping embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
