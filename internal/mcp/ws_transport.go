package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// wsTransport speaks JSON-RPC over a WebSocket (one JSON message per frame),
// with a single read loop dispatching by id like stdio.
type wsTransport struct {
	conn    *websocket.Conn
	pending pendingCalls
	notes   chan *Message
	done    chan struct{}
	writeMu sync.Mutex
	err     error
}

func startWS(ctx context.Context, name string, spec ServerSpec) (transport, error) {
	opts := &websocket.DialOptions{HTTPHeader: http.Header{}}
	for k, v := range spec.Headers {
		opts.HTTPHeader.Set(k, v)
	}
	opts.Subprotocols = []string{"mcp"}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(dialCtx, spec.URL, opts)
	if err != nil {
		return nil, fmt.Errorf("%s: ws dial: %w", name, err)
	}
	c.SetReadLimit(32 * 1024 * 1024)
	t := &wsTransport{conn: c, notes: make(chan *Message, 64), done: make(chan struct{})}
	go t.readLoop()
	return t, nil
}

func (t *wsTransport) readLoop() {
	defer close(t.done)
	defer close(t.notes)
	for {
		_, data, err := t.conn.Read(context.Background())
		if err != nil {
			t.err = err
			return
		}
		var m Message
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		dispatch(&m, &t.pending, t.notes, nil)
	}
}

func (t *wsTransport) write(m *Message) error {
	if m.JSONRPC == "" {
		m.JSONRPC = "2.0"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return t.conn.Write(context.Background(), websocket.MessageText, b)
}

func (t *wsTransport) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p, err := marshalParams(params)
	if err != nil {
		return nil, err
	}
	_, raw, ch := t.pending.newID()
	if err := t.write(&Message{ID: raw, Method: method, Params: p}); err != nil {
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
		return nil, fmt.Errorf("ws connection closed: %v", t.err)
	}
}

func (t *wsTransport) Notify(method string, params any) error {
	p, err := marshalParams(params)
	if err != nil {
		return err
	}
	return t.write(&Message{Method: method, Params: p})
}

func (t *wsTransport) Notifications() <-chan *Message { return t.notes }

func (t *wsTransport) Close() error {
	return t.conn.Close(websocket.StatusNormalClosure, "")
}
