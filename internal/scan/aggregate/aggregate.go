// Package aggregate looks across documents for what no single document
// shows: instruction-like content spread over several files. Two checks run
// after the per-file scan:
//
//  1. Joined view. All instruction files are concatenated in load order and
//     scanned as one document. Findings that only appear in the joined view
//     (their fragments straddle file boundaries) are reported at repo level.
//  2. Weak signals. Findings the policy suppressed for low confidence are
//     counted; instruction-like fragments spread over several files, or
//     piling up in one, become a medium finding.
package aggregate

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan"
)

// Thresholds for the weak-signal check.
const (
	MinFilesSpread = 3 // distinct files with weak instruction fragments
	MinHitsSpread  = 4 // total fragments across those files
	MinHitsOneFile = 5 // fragments in a single file
)

// Source names of repo-level verdicts.
const (
	SourceJoined = "aggregate:instructions-joined"
	SourceSpread = "aggregate:weak-signals"
)

// Aggregator collects per-file results and produces repo-level verdicts.
type Aggregator struct {
	scanner *scan.Scanner
	policy  scan.Policy
	instr   []part
	seen    map[string]bool // category|excerpt keys already reported per file
	weak    map[string][]scan.Finding
}

type part struct {
	source string
	text   string
}

// New creates an aggregator that scans joined views with sc.
func New(sc *scan.Scanner, pol scan.Policy) *Aggregator {
	return &Aggregator{scanner: sc, policy: pol, seen: map[string]bool{}, weak: map[string][]scan.Finding{}}
}

// Add records one document and its verdict. doc.Raw must still be set.
func (a *Aggregator) Add(doc *scan.Document, v scan.Verdict) {
	if doc.Kind == scan.KindInstructions {
		a.instr = append(a.instr, part{source: doc.Source, text: doc.Raw})
	}
	for _, f := range v.Findings {
		a.seen[key(f)] = true
	}
	for _, f := range v.Suppressed {
		if instructionLike(f.Category) {
			a.weak[doc.Source] = append(a.weak[doc.Source], f)
		}
	}
}

// Finish returns zero or more repo-level verdicts.
func (a *Aggregator) Finish(ctx context.Context) []scan.Verdict {
	var out []scan.Verdict
	if v, ok := a.joined(ctx); ok {
		out = append(out, v)
	}
	if v, ok := a.spread(); ok {
		out = append(out, v)
	}
	return out
}

func (a *Aggregator) joined(ctx context.Context) (scan.Verdict, bool) {
	if len(a.instr) < 2 {
		return scan.Verdict{}, false
	}
	sort.Slice(a.instr, func(i, j int) bool { return a.instr[i].source < a.instr[j].source })
	var b strings.Builder
	var bounds []int // byte offset where each file starts in the joined text
	for _, p := range a.instr {
		bounds = append(bounds, b.Len())
		b.WriteString(p.text)
		if !strings.HasSuffix(p.text, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	doc := &scan.Document{Source: SourceJoined, Kind: scan.KindAggregate, Raw: b.String()}
	v := a.scanner.Scan(ctx, doc)
	var fresh []scan.Finding
	for _, f := range v.Findings {
		if a.seen[key(f)] {
			continue // already reported for its own file
		}
		f.Message = strings.TrimSpace(f.Message + " (visible only when instruction files are combined: " + filesFor(a.instr, bounds, f.Span) + ")")
		fresh = append(fresh, f)
	}
	if len(fresh) == 0 {
		return scan.Verdict{}, false
	}
	return a.policy.Decide(doc, fresh), true
}

func (a *Aggregator) spread() (scan.Verdict, bool) {
	total := 0
	var files []string
	for src, fs := range a.weak {
		if len(fs) == 0 {
			continue
		}
		files = append(files, src)
		total += len(fs)
	}
	sort.Strings(files)
	var msg string
	switch {
	case len(files) >= MinFilesSpread && total >= MinHitsSpread:
		msg = fmt.Sprintf("%d weak instruction-like fragments spread across %d files", total, len(files))
	case len(files) == 1 && total >= MinHitsOneFile:
		msg = fmt.Sprintf("%d weak instruction-like fragments in %s", total, files[0])
	default:
		return scan.Verdict{}, false
	}
	conf := 0.5 + float64(total)/20
	if conf > 0.85 {
		conf = 0.85
	}
	// One finding per file so the report shows where to look.
	var findings []scan.Finding
	for _, src := range files {
		fs := a.weak[src]
		findings = append(findings, scan.Finding{
			Category:   scan.CatInstructionOverride,
			Level:      scan.LevelMedium,
			Confidence: conf,
			Detector:   "aggregate",
			Source:     src,
			Line:       fs[0].Line,
			Span:       fs[0].Span,
			Excerpt:    fs[0].Excerpt,
			Message:    fmt.Sprintf("%s; %d fragment(s) here", msg, len(fs)),
		})
	}
	doc := &scan.Document{Source: SourceSpread, Kind: scan.KindAggregate}
	return a.policy.Decide(doc, findings), true
}

func instructionLike(c scan.Category) bool {
	return c == scan.CatInstructionOverride || c == scan.CatSystemPrompt || c == scan.CatHiddenText
}

func key(f scan.Finding) string {
	return string(f.Category) + "|" + strings.TrimSpace(f.Excerpt)
}

func filesFor(parts []part, bounds []int, sp scan.Span) string {
	var names []string
	for i, start := range bounds {
		end := start + len(parts[i].text) + 2
		if sp.Start < end && sp.End > start {
			names = append(names, parts[i].source)
		}
	}
	return strings.Join(names, ", ")
}
