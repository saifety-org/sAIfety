package detect

import (
	"testing"

	"github.com/saifety-org/sAIfety/internal/scan"
)

// Common code identifiers must not trip command patterns (regression for a
// false positive where `age`, `wipe`, `enc` in Go source were flagged).
func TestCodeIdentifiersNotFlagged(t *testing.T) {
	src := `package search

type Filter struct {
	age   int
	name  string
}

func (f *Filter) wipe() { f.age = 0 }

func encode(enc *Encoder, age int) string {
	return enc.String() + fmt.Sprint(age)
}
`
	doc := &scan.Document{Source: "internal/search/parser.go", Kind: scan.KindFile, Raw: src, Text: src}
	for _, d := range Default() {
		for _, f := range d.Detect(doc, src) {
			if f.Category == scan.CatEncryption || f.Category == scan.CatDeletion {
				t.Errorf("false positive %s at %v: %q", f.Category, f.Span, src[f.Span.Start:min(f.Span.End, len(src))])
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
