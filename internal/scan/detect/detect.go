// Package detect implements the built-in detectors. Each one is small and
// rule-based; the ML classifier lives in scan/classify and plugs in through
// the same scan.Detector interface.
package detect

import (
	"regexp"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// Default returns the standard detector set in evaluation order.
func Default() []scan.Detector {
	return []scan.Detector{
		NewPatterns("instruction", rules.Instruction),
		NewPatterns("weak", rules.Weak),
		NewPatterns("command", rules.Command),
		Shell{},
		AbortBait{},
		Obfuscation{},
		Hidden{},
		Encoded{},
		AgentConfig{},
	}
}

// Patterns is a generic regex detector over a rules.Pattern list.
type Patterns struct {
	name  string
	rules []compiled
}

type compiled struct {
	rules.Pattern
	re *regexp.Regexp
}

// NewPatterns compiles pats case-insensitively. Panics on a bad pattern,
// which is a programming error in the embedded table.
func NewPatterns(name string, pats []rules.Pattern) *Patterns {
	p := &Patterns{name: name}
	for _, r := range pats {
		p.rules = append(p.rules, compiled{Pattern: r, re: regexp.MustCompile(`(?im)` + r.Regex)})
	}
	return p
}

func (p *Patterns) Name() string { return p.name }

func (p *Patterns) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding
	for _, r := range p.rules {
		for _, m := range r.re.FindAllStringIndex(text, -1) {
			conf := r.Confidence
			// Instruction files are where instructions legitimately live,
			// so a match there is only suspicious when it targets the
			// agent's obedience rather than describing the project.
			if doc.Kind == scan.KindInstructions && r.Category == scan.CatSystemPrompt {
				conf *= 0.8
			}
			// Command-looking text inside a fenced code block of an
			// ordinary file is documentation, not an instruction to run.
			// Halving keeps "curl | sh" visible and drops "npm install".
			if p.name == "command" && doc.Kind == scan.KindFile && (inCodeFence(text, m[0]) || inInlineCode(text, m[0])) {
				conf *= 0.5
			}
			out = append(out, scan.Finding{
				Category:   r.Category,
				Level:      rules.Impact[r.Category],
				Confidence: conf,
				Span:       scan.Span{Start: m[0], End: m[1]},
				Message:    r.Note,
			})
		}
	}
	return out
}

// inCodeFence reports whether offset lies between ``` markers.
func inCodeFence(text string, off int) bool {
	return strings.Count(text[:off], "```")%2 == 1
}

// inInlineCode reports whether offset lies inside `...` on its line.
func inInlineCode(text string, off int) bool {
	lineStart := strings.LastIndexByte(text[:off], '\n') + 1
	return strings.Count(text[lineStart:off], "`")%2 == 1
}
