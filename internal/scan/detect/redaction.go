package detect

import (
	"github.com/alexandr-mironov/saifety/internal/scan"
	"github.com/alexandr-mironov/saifety/internal/scan/redact"
	"github.com/alexandr-mironov/saifety/internal/scan/rules"
)

// Redaction surfaces secrets and personal data as findings. It does not
// block: exposed sensitive data is masked (by the proxy/hook output path),
// not treated as an attack on the source. The scanner reports it so a repo
// scan flags leaked credentials and PII.
type Redaction struct {
	Opts redact.Options
}

func (Redaction) Name() string { return "redaction" }

func (d Redaction) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding
	for _, m := range redact.Find(text, d.Opts) {
		cat := scan.CatSecret
		switch m.Kind {
		case redact.KindPII:
			cat = scan.CatPII
		case redact.KindAuth, redact.KindSecret:
			cat = scan.CatSecret
		case redact.KindCustom:
			cat = scan.CatPII
		}
		out = append(out, scan.Finding{
			Category:   cat,
			Level:      rules.Impact[cat],
			Confidence: m.Confidence,
			Span:       scan.Span{Start: m.Start, End: m.End},
			Message:    string(m.Kind) + "/" + m.Label + " present; will be masked before the agent sees it",
		})
	}
	return out
}
