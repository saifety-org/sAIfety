package sanitize

import (
	"strings"
	"testing"

	"github.com/alexandr-mironov/saifety/internal/scan"
)

func TestStripRemovesMediumSpans(t *testing.T) {
	text := "keep this. DROP THIS. keep that."
	v := scan.Verdict{Source: "s", Level: scan.LevelMedium, Action: scan.ActionSanitize, Findings: []scan.Finding{
		{Category: scan.CatExfiltration, Level: scan.LevelMedium, Span: scan.Span{Start: 11, End: 21}},
		{Category: scan.CatInstall, Level: scan.LevelBase, Span: scan.Span{Start: 0, End: 4}}, // base is kept
	}}
	out := Apply(text, v)
	if strings.Contains(out, "DROP THIS") || !strings.Contains(out, "keep this") || !strings.Contains(out, "keep that") {
		t.Fatalf("bad strip: %q", out)
	}
	if !strings.Contains(out, "```saifety-untrusted-data") {
		t.Fatal("sanitized output must be wrapped")
	}
}

func TestWrapEscapesFences(t *testing.T) {
	v := scan.Verdict{Source: "s", Level: scan.LevelBase, Action: scan.ActionWarn}
	out := Apply("```sh\nrm -rf /\n```", v)
	if strings.Count(out, "```") != 2 {
		t.Fatalf("inner fences must be escaped: %q", out)
	}
}

func TestBlockHidesContent(t *testing.T) {
	v := scan.Verdict{Source: "s", Level: scan.LevelCritical, Action: scan.ActionBlock}
	out := Apply("secret payload", v)
	if strings.Contains(out, "secret payload") {
		t.Fatal("blocked content leaked")
	}
}
