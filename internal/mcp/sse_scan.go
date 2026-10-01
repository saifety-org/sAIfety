package mcp

import (
	"bufio"
	"io"
	"net/url"
	"strings"
)

// typedEvent is one SSE event with its optional type.
type typedEvent struct {
	event string
	data  string
}

// sseTypedEvents parses an SSE stream preserving the event name, needed by
// the legacy transport to spot the "endpoint" event.
func sseTypedEvents(r io.Reader) <-chan typedEvent {
	out := make(chan typedEvent)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		var ev typedEvent
		var data []string
		flush := func() {
			if len(data) > 0 || ev.event != "" {
				ev.data = strings.Join(data, "\n")
				out <- ev
			}
			ev = typedEvent{}
			data = nil
		}
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				flush()
			case strings.HasPrefix(line, "event:"):
				ev.event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			}
		}
		flush()
	}()
	return out
}

// resolveRef resolves a possibly-relative endpoint URL against the SSE URL.
func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}
