package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// httpTransport implements the MCP "Streamable HTTP" transport: each request
// is an HTTP POST whose response is either a single JSON-RPC message
// (application/json) or an SSE stream (text/event-stream) carrying the
// response and possibly interleaved notifications. A session id returned on
// initialize is echoed on every later request.
type httpTransport struct {
	url    string
	header http.Header
	client *http.Client

	mu        sync.Mutex
	sessionID string
	notes     chan *Message
	protocol  string
}

func startHTTP(ctx context.Context, name string, spec ServerSpec) (transport, error) {
	h := http.Header{}
	for k, v := range spec.Headers {
		h.Set(k, v)
	}
	return &httpTransport{
		url:    spec.URL,
		header: h,
		client: &http.Client{},
		notes:  make(chan *Message, 64),
	}, nil
}

func (t *httpTransport) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p, err := marshalParams(params)
	if err != nil {
		return nil, err
	}
	req := &Message{JSONRPC: "2.0", ID: json.RawMessage(`"1"`), Method: method, Params: p}
	body, _ := json.Marshal(req)
	resp, ctype, err := t.post(ctx, body, true)
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	if strings.HasPrefix(ctype, "application/json") {
		var m Message
		if err := json.NewDecoder(resp).Decode(&m); err != nil {
			return nil, err
		}
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	}
	// SSE: read events until the JSON-RPC response arrives; forward any
	// notifications that come alongside it.
	return t.readSSEUntilResponse(resp)
}

func (t *httpTransport) Notify(method string, params any) error {
	p, err := marshalParams(params)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(&Message{JSONRPC: "2.0", Method: method, Params: p})
	resp, _, err := t.post(context.Background(), body, false)
	if err != nil {
		return err
	}
	resp.Close()
	return nil
}

func (t *httpTransport) post(ctx context.Context, body []byte, wantResp bool) (io.ReadCloser, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	for k, vs := range t.header {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	t.mu.Lock()
	if t.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", t.sessionID)
	}
	if t.protocol != "" {
		httpReq.Header.Set("MCP-Protocol-Version", t.protocol)
	}
	t.mu.Unlock()

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.mu.Lock()
		t.sessionID = sid
		t.mu.Unlock()
	}
	if resp.StatusCode == http.StatusAccepted { // 202 for notifications
		return resp.Body, resp.Header.Get("Content-Type"), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, "", fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return resp.Body, resp.Header.Get("Content-Type"), nil
}

func (t *httpTransport) readSSEUntilResponse(r io.Reader) (json.RawMessage, error) {
	for ev := range sseEvents(r) {
		var m Message
		if json.Unmarshal([]byte(ev), &m) != nil {
			continue
		}
		if m.IsResponse() {
			if m.Error != nil {
				return nil, m.Error
			}
			return m.Result, nil
		}
		if m.IsNotification() {
			select {
			case t.notes <- &m:
			default:
			}
		}
	}
	return nil, fmt.Errorf("stream ended before a response")
}

func (t *httpTransport) Notifications() <-chan *Message { return t.notes }

func (t *httpTransport) Close() error {
	// Best-effort session teardown per the spec (DELETE with the session id).
	t.mu.Lock()
	sid := t.sessionID
	t.mu.Unlock()
	if sid == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete, t.url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Mcp-Session-Id", sid)
	if resp, err := t.client.Do(req); err == nil {
		resp.Body.Close()
	}
	return nil
}

// sseEvents yields the data payload of each SSE event from r. It joins
// multi-line data fields with newlines and emits on a blank line.
func sseEvents(r io.Reader) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		var data []string
		flush := func() {
			if len(data) > 0 {
				out <- strings.Join(data, "\n")
				data = nil
			}
		}
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				flush()
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			case strings.HasPrefix(line, ":"):
				// comment/keep-alive, ignore
			}
		}
		flush()
	}()
	return out
}
