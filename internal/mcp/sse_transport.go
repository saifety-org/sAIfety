package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// sseTransport implements the legacy MCP HTTP+SSE transport (protocol
// 2024-11-05): the client opens a long-lived GET SSE stream, the server's
// first "endpoint" event gives a URL to POST requests to, and all responses
// and notifications arrive back on the SSE stream. One read loop over the
// stream dispatches by id, like stdio.
type sseTransport struct {
	getURL  string
	header  http.Header
	client  *http.Client
	pending pendingCalls
	notes   chan *Message
	done    chan struct{}
	err     error

	mu        sync.Mutex
	postURL   string
	postReady chan struct{}
	body      io.Closer
}

func startSSE(ctx context.Context, name string, spec ServerSpec) (transport, error) {
	h := http.Header{}
	for k, v := range spec.Headers {
		h.Set(k, v)
	}
	t := &sseTransport{
		getURL:    spec.URL,
		header:    h,
		client:    &http.Client{},
		notes:     make(chan *Message, 64),
		done:      make(chan struct{}),
		postReady: make(chan struct{}),
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, spec.URL, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: sse connect: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: sse http %d", name, resp.StatusCode)
	}
	t.body = resp.Body
	go t.readLoop(resp.Body)
	// Wait briefly for the endpoint event so the first Call has a POST URL.
	select {
	case <-t.postReady:
	case <-time.After(10 * time.Second):
		resp.Body.Close()
		return nil, fmt.Errorf("%s: no endpoint event from sse server", name)
	}
	return t, nil
}

func (t *sseTransport) readLoop(r io.Reader) {
	defer close(t.done)
	defer close(t.notes)
	// The legacy transport labels events; we need the event name too, so
	// parse events with their type here rather than via sseEvents.
	for ev := range sseTypedEvents(r) {
		if ev.event == "endpoint" {
			t.mu.Lock()
			if t.postURL == "" {
				t.postURL = resolveRef(t.getURL, ev.data)
				close(t.postReady)
			}
			t.mu.Unlock()
			continue
		}
		var m Message
		if json.Unmarshal([]byte(ev.data), &m) != nil {
			continue
		}
		dispatch(&m, &t.pending, t.notes, nil)
	}
}

func (t *sseTransport) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p, err := marshalParams(params)
	if err != nil {
		return nil, err
	}
	_, raw, ch := t.pending.newID()
	body, _ := json.Marshal(&Message{JSONRPC: "2.0", ID: raw, Method: method, Params: p})
	if err := t.postMessage(ctx, body); err != nil {
		t.pending.cancel(raw)
		return nil, err
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	case <-ctx.Done():
		t.pending.cancel(raw)
		return nil, ctx.Err()
	case <-t.done:
		return nil, fmt.Errorf("sse connection closed: %v", t.err)
	}
}

func (t *sseTransport) Notify(method string, params any) error {
	p, err := marshalParams(params)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(&Message{JSONRPC: "2.0", Method: method, Params: p})
	return t.postMessage(context.Background(), body)
}

func (t *sseTransport) postMessage(ctx context.Context, body []byte) error {
	t.mu.Lock()
	url := t.postURL
	t.mu.Unlock()
	if url == "" {
		return fmt.Errorf("sse endpoint not ready")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, vs := range t.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sse post http %d", resp.StatusCode)
	}
	return nil
}

func (t *sseTransport) Notifications() <-chan *Message { return t.notes }

func (t *sseTransport) Close() error {
	if t.body != nil {
		return t.body.Close()
	}
	return nil
}
