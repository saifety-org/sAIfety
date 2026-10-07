package aggregate

import (
	"context"
	"fmt"
	"testing"

	"github.com/saifety-org/sAIfety/internal/policy"
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/detect"
)

func setup() (*scan.Scanner, *Aggregator) {
	pol := policy.New(policy.Default)
	sc := scan.New(detect.Default(), pol, scan.Options{})
	return sc, New(sc, pol)
}

// Weak phrases are ordinary prose on their own ("the assistant should be
// polite" is a fine sentence in a style guide); only their spread across
// files is a signal.
func TestWeakSignalsAcrossFiles(t *testing.T) {
	sc, agg := setup()
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		raw := fmt.Sprintf("Guide %d.\n\nThe assistant should keep answers short.\n", i)
		doc := &scan.Document{Source: fmt.Sprintf("docs/g%d.md", i), Kind: scan.KindFile, Raw: raw}
		v := sc.Scan(ctx, doc)
		if v.Level != scan.LevelNone {
			t.Fatalf("a single weak phrase must not raise a file: %+v", v)
		}
		agg.Add(doc, v)
	}
	out := agg.Finish(ctx)
	if len(out) != 1 || out[0].Source != SourceSpread || out[0].Level < scan.LevelBase {
		t.Fatalf("expected a repo-level weak-signal verdict, got %+v", out)
	}
}

func TestNoAggregateForCleanRepo(t *testing.T) {
	sc, agg := setup()
	ctx := context.Background()
	for i, raw := range []string{"# A\n\nBuild with make.\n", "# B\n\nRun the tests.\n", "# C\n\nDeploy with helm.\n"} {
		doc := &scan.Document{Source: fmt.Sprintf("f%d/CLAUDE.md", i), Kind: scan.KindInstructions, Raw: raw}
		agg.Add(doc, sc.Scan(ctx, doc))
	}
	if out := agg.Finish(ctx); len(out) != 0 {
		t.Fatalf("clean repo produced aggregate verdicts: %+v", out)
	}
}
