package detect

import (
	"regexp"

	"github.com/saifety-org/sAIfety/internal/scan"
	"github.com/saifety-org/sAIfety/internal/scan/normalize"
	"github.com/saifety-org/sAIfety/internal/scan/rules"
)

// Hidden finds text that a human would not see but a model would read:
// invisible Unicode, HTML comments carrying instructions, CSS-hidden spans.
type Hidden struct{}

func (Hidden) Name() string { return "hidden" }

var (
	reHTMLComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reMDComment   = regexp.MustCompile(`(?m)^\[[^\]]*\]:\s*#\s*\((.*)\)\s*$`)
	reCSSHidden   = regexp.MustCompile(`(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(white|#fff(fff)?|transparent)|opacity\s*:\s*0)[^>]*>`)
	reHiddenAttr  = regexp.MustCompile(`(?i)<[a-z]+[^>]*\b(hidden|aria-hidden="true")\b`)
	instrWords    = regexp.MustCompile(`(?i)(instruction|ignore|assistant|agent|claude|gpt|model|system|инструкц|игнорир|ассистент|агент)`)
)

func (Hidden) Detect(doc *scan.Document, text string) []scan.Finding {
	var out []scan.Finding

	// Invisible runes are removed by normalization, so look at the raw
	// text for the top layer. Spans are reported against the raw text.
	if text == doc.Text {
		count, first, last := 0, -1, 0
		for i, r := range doc.Raw {
			if normalize.Invisible(r) {
				count++
				if first < 0 {
					first = i
				}
				last = i
			}
		}
		if count >= 3 {
			out = append(out, scan.Finding{
				Category:   scan.CatHiddenText,
				Level:      rules.Impact[scan.CatHiddenText],
				Confidence: minf(0.5+float64(count)/40, 0.95),
				Span:       scan.Span{Start: first, End: last + 1},
				Excerpt:    "(invisible characters)",
				Message:    "zero-width or bidi control characters",
			})
		}
	}

	for _, m := range reHTMLComment.FindAllStringSubmatchIndex(text, -1) {
		body := text[m[2]:m[3]]
		if instrWords.MatchString(body) {
			out = append(out, scan.Finding{
				Category: scan.CatHiddenText, Level: rules.Impact[scan.CatHiddenText], Confidence: 0.7,
				Span: scan.Span{Start: m[0], End: m[1]}, Message: "HTML comment addressed to the model",
			})
		}
	}
	for _, m := range reMDComment.FindAllStringIndex(text, -1) {
		out = append(out, scan.Finding{
			Category: scan.CatHiddenText, Level: rules.Impact[scan.CatHiddenText], Confidence: 0.5,
			Span: scan.Span{Start: m[0], End: m[1]}, Message: "markdown comment",
		})
	}
	for _, re := range []*regexp.Regexp{reCSSHidden, reHiddenAttr} {
		for _, m := range re.FindAllStringIndex(text, -1) {
			out = append(out, scan.Finding{
				Category: scan.CatHiddenText, Level: rules.Impact[scan.CatHiddenText], Confidence: 0.6,
				Span: scan.Span{Start: m[0], End: m[1]}, Message: "CSS/attribute-hidden content",
			})
		}
	}
	return out
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
