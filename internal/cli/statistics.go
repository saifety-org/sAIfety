package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/saifety-org/sAIfety/internal/stats"
)

func runStatistics(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	reset := false
	format := "text"
	var scope string
	for _, a := range args {
		switch a {
		case "-reset", "--reset":
			reset = true
		case "-json", "--json":
			format = "json"
		default:
			if a != "" && a[0] != '-' {
				scope = a
			}
		}
	}

	scopes := stats.Scopes
	if scope != "" {
		if !validScope(scope) {
			fmt.Fprintf(stderr, "unknown scope %q (use: %v)\n", scope, stats.Scopes)
			return ExitUsage
		}
		scopes = []string{scope}
	}

	if reset {
		for _, sc := range scopes {
			s, err := stats.Load(stats.ScopePath(sc))
			if err != nil {
				continue
			}
			_ = s.Reset()
		}
		fmt.Fprintf(stdout, "statistics reset: %v\n", scopes)
		return ExitClean
	}

	data := map[string]stats.Data{}
	for _, sc := range scopes {
		s, err := stats.Load(stats.ScopePath(sc))
		if err != nil {
			fmt.Fprintf(stderr, "stats %s: %v\n", sc, err)
			continue
		}
		data[sc] = s.Snapshot()
	}

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(data); err != nil {
			return ExitError
		}
		return ExitClean
	}

	for _, sc := range scopes {
		renderScope(stdout, sc, data[sc])
	}
	return ExitClean
}

func validScope(s string) bool {
	for _, sc := range stats.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

func renderScope(w io.Writer, scope string, d stats.Data) {
	fmt.Fprintf(w, "== %s (%s) ==\n", scope, stats.ScopePath(scope))
	if d.Documents == 0 {
		fmt.Fprint(w, "  (no activity recorded yet)\n\n")
		return
	}
	fmt.Fprintf(w, "  documents scanned : %d\n", d.Documents)
	fmt.Fprintf(w, "  total findings    : %d\n", d.Findings)
	fmt.Fprintf(w, "  actions           : blocked %d, sanitized %d, warned %d\n", d.Blocked, d.Sanitized, d.Warned)
	if !d.FirstSeen.IsZero() {
		fmt.Fprintf(w, "  period            : %s .. %s\n", d.FirstSeen.Format("2006-01-02 15:04"), d.LastSeen.Format("2006-01-02 15:04"))
	}
	printCounts(w, "  by level", d.ByLevel)
	printCounts(w, "  by category", d.ByCategory)
	printTop(w, "  top sources", d.BySource, 10)
	fmt.Fprintln(w)
}

func printCounts(w io.Writer, title string, m map[string]int) {
	if len(m) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", title)
	for _, kv := range stats.SortedCounts(m) {
		fmt.Fprintf(w, "    %-20s %d\n", kv.Key, kv.Count)
	}
}

func printTop(w io.Writer, title string, m map[string]int, n int) {
	if len(m) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", title)
	for i, kv := range stats.SortedCounts(m) {
		if i >= n {
			break
		}
		fmt.Fprintf(w, "    %-40s %d\n", kv.Key, kv.Count)
	}
}
