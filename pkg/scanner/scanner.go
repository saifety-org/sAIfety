// Package scanner provides offline document scanning and sanitization using
// the same detectors, policies and aggregation as the sAIfety application.
package scanner

import (
	"context"
	"fmt"

	"github.com/saifety-org/sAIfety/internal/policy"
	"github.com/saifety-org/sAIfety/internal/sanitize"
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/aggregate"
	"github.com/saifety-org/sAIfety/internal/scan/classify"
	"github.com/saifety-org/sAIfety/internal/scan/detect"
	"github.com/saifety-org/sAIfety/internal/walk"
	"github.com/saifety-org/sAIfety/pkg/inference"
)

type Document = scan.Document
type Verdict = scan.Verdict
type Kind = scan.Kind
type Category = scan.Category
type Level = scan.Level

const (
	LevelNone           = scan.LevelNone
	LevelBase           = scan.LevelBase
	LevelMedium         = scan.LevelMedium
	LevelCritical       = scan.LevelCritical
	ActionBlock         = scan.ActionBlock
	KindFile            = scan.KindFile
	KindInstructions    = scan.KindInstructions
	KindAgentConfig     = scan.KindAgentConfig
	KindToolResult      = scan.KindToolResult
	KindToolDescription = scan.KindToolDescription
	KindImage           = scan.KindImage
	KindAggregate       = scan.KindAggregate
)

// Config selects policy and a classifier. Empty Policy selects strict; nil
// Classifier runs only the rule detectors. Output secret/PII masking and MCP
// tool integrity are separate application layers, not part of this API.
type Config struct {
	Policy         string
	Classifier     inference.Scorer
	MaxDecodeDepth int
}

type Scanner struct {
	scanner *scan.Scanner
	policy  scan.Policy
}

func New(cfg Config) (*Scanner, error) {
	profile := policy.Strict
	switch cfg.Policy {
	case "", "strict":
	case "balanced":
		profile = policy.Default
	default:
		return nil, fmt.Errorf("unknown policy %q", cfg.Policy)
	}
	pol := policy.New(profile)
	detectors := detect.Default()
	if cfg.Classifier != nil {
		detectors = append(detectors, classify.Detector{C: cfg.Classifier})
	}
	return &Scanner{scanner: scan.New(detectors, pol, scan.Options{MaxDecodeDepth: cfg.MaxDecodeDepth}), policy: pol}, nil
}

// Scan normalizes doc.Text and returns its verdict. It executes no content.
func (s *Scanner) Scan(ctx context.Context, doc *Document) Verdict { return s.scanner.Scan(ctx, doc) }

// ScanDocuments returns per-document verdicts followed by aggregate findings.
// Aggregation is scoped to this call; documents from earlier calls are not reused.
func (s *Scanner) ScanDocuments(ctx context.Context, docs []*Document) []Verdict {
	agg := aggregate.New(s.scanner, s.policy)
	out := make([]Verdict, 0, len(docs))
	for _, doc := range docs {
		v := s.Scan(ctx, doc)
		agg.Add(doc, v)
		out = append(out, v)
	}
	return append(out, agg.Finish(ctx)...)
}

// Sanitize applies a verdict to the normalized document after scanning.
func Sanitize(doc *Document, verdict Verdict) string { return sanitize.Apply(doc.Text, verdict) }

func ParseLevel(value string) (Level, bool) { return scan.ParseLevel(value) }
func KindForPath(path string) Kind          { return walk.Classify(path) }
