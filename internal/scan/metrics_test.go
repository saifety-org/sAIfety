package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexandr-mironov/saifety/internal/policy"
	"github.com/alexandr-mironov/saifety/internal/scan"
	"github.com/alexandr-mironov/saifety/internal/scan/classify"
	"github.com/alexandr-mironov/saifety/internal/scan/detect"
	"github.com/alexandr-mironov/saifety/internal/walk"
)

// The corpus is the ground truth for calibration: every file under
// malicious/ must reach at least base, every file under benign/ must stay
// clean or at most base-with-warn (never medium+). This test is the guard
// against regressions when rules or the classifier change.
//
// Run `go test ./internal/scan -run Corpus -v` to see per-sample scores.

const (
	corpusDir      = "../../testdata/corpus"
	maxBenignLevel = scan.LevelBase // benign may warn, must not sanitize/block
)

func corpusScanner() *scan.Scanner {
	detectors := append(detect.Default(), classify.Detector{C: classify.Lexical{}})
	return scan.New(detectors, policy.New(policy.Default), scan.Options{})
}

func scoreFile(t *testing.T, sc *scan.Scanner, path string) scan.Verdict {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rel, _ := filepath.Rel(corpusDir, path)
	kind := walk.Classify(rel)
	return sc.Scan(context.Background(), &scan.Document{Source: rel, Kind: kind, Raw: string(raw)})
}

func listCorpus(t *testing.T, sub string) []string {
	entries, err := os.ReadDir(filepath.Join(corpusDir, sub))
	if err != nil {
		t.Skipf("corpus %s not present: %v", sub, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, filepath.Join(corpusDir, sub, e.Name()))
		}
	}
	return out
}

func TestCorpusMetrics(t *testing.T) {
	sc := corpusScanner()
	mal := listCorpus(t, "malicious")
	ben := listCorpus(t, "benign")

	var tp, fn, tn, fp int
	for _, p := range mal {
		v := scoreFile(t, sc, p)
		if v.Level >= scan.LevelBase {
			tp++
		} else {
			fn++
			t.Errorf("MISS (false negative): %s scored %s", filepath.Base(p), v.Level)
		}
	}
	for _, p := range ben {
		v := scoreFile(t, sc, p)
		if v.Level <= maxBenignLevel {
			tn++
		} else {
			fp++
			var cats []string
			for _, f := range v.Findings {
				cats = append(cats, string(f.Category))
			}
			t.Errorf("FALSE POSITIVE: %s scored %s %v", filepath.Base(p), v.Level, cats)
		}
	}

	total := tp + fn + tn + fp
	precision := ratio(tp, tp+fp)
	recall := ratio(tp, tp+fn)
	t.Logf("corpus: %d samples | recall=%.2f precision=%.2f | TP=%d FN=%d TN=%d FP=%d",
		total, recall, precision, tp, fn, tn, fp)

	if recall < 1.0 {
		t.Errorf("recall %.2f < 1.0: every malicious sample must be caught", recall)
	}
	if precision < 1.0 {
		t.Errorf("precision %.2f < 1.0: benign samples must not exceed %s", precision, maxBenignLevel)
	}
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 1
	}
	return float64(n) / float64(d)
}
