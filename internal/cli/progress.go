package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// scanProgress shows live scan progress on a terminal so a long scan does not
// look frozen. It writes to stderr (the report goes to stdout) and only
// animates when stderr is a terminal; in a pipe or CI it stays silent.
type scanProgress struct {
	w       io.Writer
	total   int
	count   int
	tty     bool
	last    time.Time
	started time.Time
}

func newScanProgress(w io.Writer, total int) *scanProgress {
	return &scanProgress{w: w, total: total, tty: isTerminal(w), started: time.Now()}
}

// step advances the counter and refreshes the line for the file about to be
// scanned. Throttled so it does not slow the scan.
func (p *scanProgress) step(path string) {
	if p == nil {
		return
	}
	p.count++
	if !p.tty {
		return
	}
	if time.Since(p.last) < 100*time.Millisecond && p.count < p.total {
		return
	}
	p.last = time.Now()
	name := path
	if len(name) > 48 {
		name = "..." + name[len(name)-45:]
	}
	fmt.Fprintf(p.w, "\r  scanning %d/%d  %-48s", p.count, p.total, filepath.Clean(name))
}

// clear erases the progress line so a following message starts clean.
func (p *scanProgress) clear() {
	if p == nil || !p.tty {
		return
	}
	fmt.Fprint(p.w, "\r"+spaces(72)+"\r")
}

// done clears the line and prints a one-line summary of the sweep.
func (p *scanProgress) done() {
	if p == nil || !p.tty {
		return
	}
	fmt.Fprintf(p.w, "\r%s\r  scanned %d files in %.1fs\n", spaces(72), p.count, time.Since(p.started).Seconds())
}

func spaces(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

// isTerminal reports whether w is a terminal (character device).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
