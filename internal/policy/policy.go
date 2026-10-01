// Package policy maps findings to a verdict. Two axes: the impact level of
// the category (from rules) and the confidence of the detection. A trusted
// source lowers the result by one step but never below base when something
// was found, so trusted data is still labeled.
package policy

import (
	"sort"

	"github.com/alexandr-mironov/saifety/internal/scan"
)

// Config tunes the decision.
type Config struct {
	// Findings below MinConfidence are dropped entirely.
	MinConfidence float64
	// Findings below SureConfidence are downgraded one level.
	SureConfidence float64
	// TrustDowngrade lowers the level of trusted sources by one step.
	TrustDowngrade bool
}

// WeakFloor is the lowest confidence kept as a suppressed finding.
const WeakFloor = 0.2

// Default is a balanced profile; tune from real corpora later.
var Default = Config{MinConfidence: 0.4, SureConfidence: 0.7, TrustDowngrade: true}

// Strict is the default profile for the tool: it surfaces weaker findings
// (lower MinConfidence), is quicker to treat a finding as high-impact
// (lower SureConfidence), and never lowers a level because a source was
// declared trusted. Use the balanced Default profile to reduce noise.
var Strict = Config{MinConfidence: 0.25, SureConfidence: 0.55, TrustDowngrade: false}

// Policy implements scan.Policy.
type Policy struct{ cfg Config }

func New(cfg Config) *Policy {
	if cfg.MinConfidence == 0 && cfg.SureConfidence == 0 {
		cfg = Default
	}
	return &Policy{cfg: cfg}
}

// Decide computes the effective level of each finding and the document.
func (p *Policy) Decide(doc *scan.Document, findings []scan.Finding) scan.Verdict {
	v := scan.Verdict{Source: doc.Source, Kind: doc.Kind}
	for _, f := range findings {
		if f.Confidence < p.cfg.MinConfidence {
			if f.Confidence >= WeakFloor {
				v.Suppressed = append(v.Suppressed, f)
			}
			continue
		}
		lvl := f.Level
		if f.Confidence < p.cfg.SureConfidence && lvl > scan.LevelBase {
			lvl--
		}
		if doc.Trusted && p.cfg.TrustDowngrade && lvl > scan.LevelBase {
			lvl--
		}
		f.Level = lvl
		v.Findings = append(v.Findings, f)
		if lvl > v.Level {
			v.Level = lvl
		}
	}
	sort.SliceStable(v.Findings, func(i, j int) bool {
		if v.Findings[i].Level != v.Findings[j].Level {
			return v.Findings[i].Level > v.Findings[j].Level
		}
		return v.Findings[i].Span.Start < v.Findings[j].Span.Start
	})
	v.Action = ActionFor(v.Level)
	return v
}

// ActionFor is the fixed level→action mapping from README.
func ActionFor(l scan.Level) scan.Action {
	switch l {
	case scan.LevelBase:
		return scan.ActionWarn
	case scan.LevelMedium:
		return scan.ActionSanitize
	case scan.LevelCritical:
		return scan.ActionBlock
	}
	return scan.ActionPass
}
