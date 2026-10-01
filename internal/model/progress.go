package model

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// progressWriter reports download progress to w as bytes arrive. It counts
// bytes (used via io.MultiWriter next to the file) and prints a throttled
// single line: "<name>: 123.4 MB / 738.6 MB (17%) at 5.2 MB/s".
type progressWriter struct {
	w         io.Writer
	name      string
	total     int64 // expected size, 0 if unknown
	written   atomic.Int64
	start     time.Time
	lastPrint time.Time
}

func newProgress(w io.Writer, name string, total int64) *progressWriter {
	return &progressWriter{w: w, name: name, total: total, start: time.Now()}
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.written.Add(int64(n))
	if time.Since(p.lastPrint) >= 300*time.Millisecond {
		p.lastPrint = time.Now()
		p.line("\r")
	}
	return n, nil
}

func (p *progressWriter) line(prefix string) {
	got := p.written.Load()
	elapsed := time.Since(p.start).Seconds()
	speed := 0.0
	if elapsed > 0 {
		speed = float64(got) / elapsed
	}
	if p.total > 0 {
		pct := float64(got) / float64(p.total) * 100
		fmt.Fprintf(p.w, "%s    %s: %.1f MB / %.1f MB (%.0f%%) at %.1f MB/s      ",
			prefix, p.name, mb(got), mb(p.total), pct, speed/1e6)
	} else {
		fmt.Fprintf(p.w, "%s    %s: %.1f MB at %.1f MB/s      ", prefix, p.name, mb(got), speed/1e6)
	}
}

// done prints the final state and a newline.
func (p *progressWriter) done() {
	p.line("\r")
	fmt.Fprintln(p.w)
}

func mb(b int64) float64 { return float64(b) / 1e6 }
