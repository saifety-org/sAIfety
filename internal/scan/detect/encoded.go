package detect

import (
	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/decode"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// Encoded reports blobs that decode to readable text. The scanner separately
// unwraps them and runs all detectors on the content; this detector only
// flags the presence of the blob so that it is not lost when the content
// itself looks harmless.
type Encoded struct{}

func (Encoded) Name() string { return "encoded" }

func (Encoded) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding
	for _, c := range decode.Candidates(text) {
		if c.Encoding == "rot13" || c.Encoding == "entities-context" {
			continue // contextual views: only findings in the decoded text count
		}
		conf := 0.45
		if doc.Kind == scan.KindInstructions || doc.Kind == scan.KindToolDescription {
			conf = 0.7 // no reason for encoded text in instructions
		}
		out = append(out, scan.Finding{
			Category:   scan.CatEncodedPayload,
			Level:      rules.Impact[scan.CatEncodedPayload],
			Confidence: conf,
			Span:       scan.Span{Start: c.Start, End: c.End},
			Message:    c.Encoding + " blob decodes to text",
		})
	}
	return out
}
