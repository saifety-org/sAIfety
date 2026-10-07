package detect

import (
	"encoding/json"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// AgentConfig inspects agent configuration files that can execute commands:
// hook definitions in Claude Code settings and MCP server launch specs.
// A repository-supplied settings file with hooks is treated as critical: it
// runs arbitrary commands as soon as the folder is trusted.
type AgentConfig struct{}

func (AgentConfig) Name() string { return "agent_config" }

func (AgentConfig) Detect(doc *scan.Document, text string) []scan.Finding {
	if doc.Kind != scan.KindAgentConfig || text != doc.Text {
		return nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stripJSONC(text)), &root); err != nil {
		return nil
	}
	var out []scan.Finding
	if raw, ok := root["hooks"]; ok && len(raw) > 2 {
		out = append(out, scan.Finding{
			Category: scan.CatHookConfig, Level: rules.Impact[scan.CatHookConfig], Confidence: 0.9,
			Span: spanOfKey(text, `"hooks"`), Message: "settings file defines hooks that run commands",
		})
	}
	if raw, ok := root["mcpServers"]; ok && len(raw) > 2 {
		out = append(out, scan.Finding{
			Category: scan.CatArbitraryCommand, Level: scan.LevelMedium, Confidence: 0.6,
			Span: spanOfKey(text, `"mcpServers"`), Message: "config launches MCP server processes",
		})
	}
	return out
}

func spanOfKey(text, key string) scan.Span {
	i := strings.Index(text, key)
	if i < 0 {
		return scan.Span{}
	}
	return scan.Span{Start: i, End: i + len(key)}
}

// stripJSONC removes // line comments so settings files with comments parse.
func stripJSONC(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "//") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
