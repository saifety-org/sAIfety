// Package classify adapts native, lexical and optional ONNX classifiers to
// the document-scanning pipeline.
package classify

import (
	"strings"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// Classifier scores a chunk of text; 1.0 means "certainly an instruction".
type Classifier interface {
	Score(text string) float64
}

// Noop always returns 0 and therefore never produces findings.
type Noop struct{}

func (Noop) Score(string) float64 { return 0 }

// Detector adapts a Classifier to scan.Detector by scoring paragraphs.
type Detector struct {
	C         Classifier
	Threshold float64 // default 0.8
}

func (Detector) Name() string { return "classifier" }

// TopLayerOnly keeps the (possibly slow) classifier from running on every
// decoded sub-layer during a scan.
func (Detector) TopLayerOnly() bool { return true }

// maxParaBytes bounds how much of a paragraph is fed to the model (the model
// truncates to its context window anyway; this also avoids pathological
// tokenizer input). maxParas bounds how many paragraphs are scored per doc.
const (
	maxParaBytes = 8000
	maxParas     = 40
)

func (d Detector) Detect(doc *scan.Document, text string) []scan.Finding {
	if d.C == nil {
		return nil
	}
	th := d.Threshold
	if th == 0 {
		th = 0.8
	}
	// Split into paragraphs, tracking each one's byte offset.
	var probes []string
	var spans []scan.Span
	off := 0
	for i, para := range strings.Split(text, "\n\n") {
		if i < maxParas {
			probe := para
			if len(probe) > maxParaBytes {
				probe = probe[:maxParaBytes]
			}
			probes = append(probes, probe)
			spans = append(spans, scan.Span{Start: off, End: off + len(para)})
		}
		off += len(para) + 2
	}

	// Score all paragraphs, batched when the classifier supports it.
	var scores []float64
	if bc, ok := d.C.(BatchClassifier); ok {
		scores = bc.Scores(probes)
	} else {
		scores = make([]float64, len(probes))
		for i, p := range probes {
			scores[i] = d.C.Score(p)
		}
	}

	var out []scan.Finding
	for i, sc := range scores {
		if sc >= th {
			out = append(out, scan.Finding{
				Category:   scan.CatInstructionOverride,
				Level:      rules.Impact[scan.CatInstructionOverride],
				Confidence: sc,
				Span:       spans[i],
				Message:    "classified as instruction to the agent",
			})
		}
	}
	return out
}

// Gated composes a cheap classifier with an expensive one: it returns the
// cheap score for text the cheap model rates below Threshold, and only runs
// the expensive model on text above it. This keeps a slow transformer from
// running on every paragraph of a repository — the vast majority (code,
// prose) is dismissed instantly, and the model refines only candidates.
type Gated struct {
	Cheap     Classifier
	Model     Classifier
	Threshold float64 // default 0.2
}

func (g Gated) Score(text string) float64 {
	cheap := g.Cheap.Score(text)
	th := g.Threshold
	if th == 0 {
		th = 0.2
	}
	if cheap < th || g.Model == nil {
		return cheap
	}
	return g.Model.Score(text)
}

// BatchClassifier scores many texts in one shot. A transformer amortizes far
// better over a batch than over N single calls, which makes a full-repository
// deep scan practical.
type BatchClassifier interface {
	Scores(texts []string) []float64
}

// Scores implements BatchClassifier for Gated: it cheap-scores everything,
// then runs the expensive model (batched if it supports it) only on the
// candidates above the threshold.
func (g Gated) Scores(texts []string) []float64 {
	out := make([]float64, len(texts))
	th := g.Threshold
	if th == 0 {
		th = 0.2
	}
	var idx []int
	var cand []string
	for i, t := range texts {
		c := g.Cheap.Score(t)
		out[i] = c
		if c >= th && g.Model != nil {
			idx = append(idx, i)
			cand = append(cand, t)
		}
	}
	if len(cand) == 0 {
		return out
	}
	if bc, ok := g.Model.(BatchClassifier); ok {
		for k, sc := range bc.Scores(cand) {
			out[idx[k]] = sc
		}
	} else {
		for k, t := range cand {
			out[idx[k]] = g.Model.Score(t)
		}
	}
	return out
}
