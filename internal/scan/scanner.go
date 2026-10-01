package scan

import (
	"context"
	"strings"

	"github.com/alexandr-mironov/saifety/internal/scan/decode"
	"github.com/alexandr-mironov/saifety/internal/scan/normalize"
)

// Options tune the scanner.
type Options struct {
	// MaxDecodeDepth bounds how many nested encodings are unwrapped.
	MaxDecodeDepth int
	// MaxLayerBytes skips decoded layers larger than this to bound work.
	MaxLayerBytes int
}

// DefaultOptions are used when a zero Options is passed.
var DefaultOptions = Options{MaxDecodeDepth: 3, MaxLayerBytes: 1 << 20}

// Scanner runs the pipeline: normalize → (detect → decode)* → policy.
type Scanner struct {
	detectors []Detector
	policy    Policy
	opts      Options
}

// New builds a scanner. detectors and policy are injected so the core stays
// free of dependencies on rules, classifiers and configuration.
func New(detectors []Detector, policy Policy, opts Options) *Scanner {
	if opts.MaxDecodeDepth == 0 {
		opts.MaxDecodeDepth = DefaultOptions.MaxDecodeDepth
	}
	if opts.MaxLayerBytes == 0 {
		opts.MaxLayerBytes = DefaultOptions.MaxLayerBytes
	}
	return &Scanner{detectors: detectors, policy: policy, opts: opts}
}

// Scan analyzes one document and returns its verdict.
func (s *Scanner) Scan(ctx context.Context, doc *Document) Verdict {
	doc.Text = normalize.Text(doc.Raw)
	findings := dedupe(s.scanLayer(ctx, doc, doc.Text, nil, 0))
	for i := range findings {
		findings[i].Source = doc.Source
		if len(findings[i].Chain) == 0 {
			findings[i].Line = lineOf(doc.Text, findings[i].Span.Start)
		}
	}
	return s.policy.Decide(doc, findings)
}

// scanLayer runs detectors on text, then unwraps encoded blobs and recurses.
func (s *Scanner) scanLayer(ctx context.Context, doc *Document, text string, chain []string, depth int) []Finding {
	var out []Finding
	for _, d := range s.detectors {
		if ctx.Err() != nil {
			return out
		}
		// Expensive detectors (the transformer classifier) run only on the
		// top layer; decoded sub-layers are covered by the rule detectors.
		if len(chain) > 0 {
			if t, ok := d.(topLayerOnly); ok && t.TopLayerOnly() {
				continue
			}
		}
		for _, f := range d.Detect(doc, text) {
			if f.Detector == "" {
				f.Detector = d.Name()
			}
			f.Chain = append([]string(nil), chain...)
			if f.Excerpt == "" {
				f.Excerpt = excerpt(text, f.Span)
			}
			if len(chain) > 0 {
				f.Layer = text
			}
			out = append(out, f)
		}
	}
	if depth >= s.opts.MaxDecodeDepth {
		return out
	}
	for _, c := range decode.Candidates(text) {
		if len(c.Decoded) > s.opts.MaxLayerBytes {
			continue
		}
		inner := normalize.Text(c.Decoded)
		sub := s.scanLayer(ctx, doc, inner, append(append([]string(nil), chain...), c.Encoding), depth+1)
		// Findings inside a blob point at the blob in the parent layer so
		// that sanitizers can cut the whole encoded span.
		for i := range sub {
			if len(sub[i].Chain) == len(chain)+1 {
				sub[i].Span = Span{Start: c.Start, End: c.End}
			}
		}
		out = append(out, sub...)
	}
	return out
}

func excerpt(text string, sp Span) string {
	const max = 120
	start, end := sp.Start, sp.End
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	if end-start > max {
		end = start + max
	}
	return strings.ReplaceAll(text[start:end], "\n", "\\n")
}

func lineOf(text string, off int) int {
	if off > len(text) {
		off = len(text)
	}
	return 1 + strings.Count(text[:off], "\n")
}

// dedupe drops a finding when another of the same category and decode
// chain overlaps it with higher or equal confidence, so the pattern and
// shell detectors do not report one command twice.
func dedupe(in []Finding) []Finding {
	var out []Finding
	for i, f := range in {
		keep := true
		for j, g := range in {
			if i == j || f.Category != g.Category || !sameChain(f.Chain, g.Chain) {
				continue
			}
			overlap := f.Span.Start < g.Span.End && g.Span.Start < f.Span.End
			if !overlap {
				continue
			}
			if g.Confidence > f.Confidence || (g.Confidence == f.Confidence && j < i) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, f)
		}
	}
	return out
}

func sameChain(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// topLayerOnly marks a detector that should run only on the original text,
// not on decoded sub-layers, because it is expensive.
type topLayerOnly interface {
	TopLayerOnly() bool
}
