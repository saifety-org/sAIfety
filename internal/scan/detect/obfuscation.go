package detect

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/normalize"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// Obfuscation flags text that is deliberately scrambled to slip an
// instruction past a detector while a model would still read it: letters
// spaced apart ("i g n o r e"), words broken with separators
// ("i.g.n.o.r.e"), or many mixed-script tokens (homoglyph substitution). It
// is an independent, content-agnostic signal — it fires on the shape of the
// text, so it catches novel evasions even when the classifier is fooled.
type Obfuscation struct{}

func (Obfuscation) Name() string { return "obfuscation" }

var (
	// >=6 single-character alphanumeric tokens in a row (letter-spacing).
	reLetterSpacing = regexp.MustCompile(`(?:[\p{L}\p{N}][ \t]+){5,}[\p{L}\p{N}]\b`)
	// a word broken by . - _ between single characters, >=5 pieces.
	reSeparatorWord = regexp.MustCompile(`(?:[\p{L}\p{N}][._\-]){4,}[\p{L}\p{N}]`)
)

func (Obfuscation) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding
	for _, m := range reLetterSpacing.FindAllStringIndex(text, -1) {
		out = append(out, scan.Finding{
			Category: scan.CatObfuscation, Level: rules.Impact[scan.CatObfuscation], Confidence: 0.8,
			Span: scan.Span{Start: m[0], End: m[1]}, Message: "letters spaced apart to evade detection",
		})
	}
	for _, m := range reSeparatorWord.FindAllStringIndex(text, -1) {
		out = append(out, scan.Finding{
			Category: scan.CatObfuscation, Level: rules.Impact[scan.CatObfuscation], Confidence: 0.7,
			Span: scan.Span{Start: m[0], End: m[1]}, Message: "word broken with separators to evade detection",
		})
	}
	// Mixed-script density on the RAW text (before normalization folds it):
	// many Latin+Cyrillic tokens is homoglyph obfuscation.
	if text == doc.Text {
		mixed, first, last := 0, -1, 0
		off := 0
		for _, tok := range strings.Fields(doc.Raw) {
			if len([]rune(tok)) >= 3 && normalize.MixedScript(tok) && hasLetters(tok) {
				mixed++
				idx := strings.Index(doc.Raw[off:], tok) + off
				if first < 0 {
					first = idx
				}
				last = idx + len(tok)
			}
			off += len(tok)
		}
		if mixed >= 3 {
			out = append(out, scan.Finding{
				Category: scan.CatObfuscation, Level: rules.Impact[scan.CatObfuscation], Confidence: minf(0.5+float64(mixed)/20, 0.9),
				Span: scan.Span{Start: max0(first), End: last}, Message: "many mixed-script (homoglyph) tokens — likely obfuscation",
			})
		}
	}
	return out
}

func hasLetters(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func max0(x int) int {
	if x < 0 {
		return 0
	}
	return x
}
