// Package report renders verdicts for humans (text) and machines (json).
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/alexandr-mironov/saifety/internal/scan"
)

// Summary aggregates verdicts of one run.
type Summary struct {
	Scanned  int            `json:"scanned"`
	Level    scan.Level     `json:"level"`
	Verdicts []scan.Verdict `json:"verdicts"`
}

// Add records a verdict; clean verdicts are counted but not listed.
func (s *Summary) Add(v scan.Verdict) {
	s.Scanned++
	if v.Level > s.Level {
		s.Level = v.Level
	}
	if len(v.Findings) > 0 {
		s.Verdicts = append(s.Verdicts, v)
	}
}

// JSON writes the summary as indented JSON.
func JSON(w io.Writer, s *Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// Text writes a human-readable report.
func Text(w io.Writer, s *Summary, verbose bool) {
	for _, v := range s.Verdicts {
		fmt.Fprintf(w, "%-8s %-8s %s\n", v.Level, v.Action, v.Source)
		for _, f := range v.Findings {
			loc := ""
			if f.Line > 0 {
				loc = fmt.Sprintf(":%d", f.Line)
			}
			chain := ""
			if len(f.Chain) > 0 {
				chain = fmt.Sprintf(" via %v", f.Chain)
			}
			fmt.Fprintf(w, "    %-8s %-20s %.2f %s%s%s\n", f.Level, f.Category, f.Confidence, f.Detector, loc, chain)
			if verbose {
				fmt.Fprintf(w, "             %s\n", f.Excerpt)
				if f.Message != "" {
					fmt.Fprintf(w, "             %s\n", f.Message)
				}
			}
		}
	}
	fmt.Fprintf(w, "\n%d files scanned, %d with findings, max level: %s\n", s.Scanned, len(s.Verdicts), s.Level)
}
