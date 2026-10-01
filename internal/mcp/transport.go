package mcp

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"
)

// transport is one connection to an upstream MCP server. Implementations
// cover the MCP transports: stdio (child process), streamable HTTP, legacy
// HTTP+SSE, and WebSocket. The proxy talks to all of them the same way.
type transport interface {
	// Call sends a request and waits for its response.
	Call(ctx context.Context, method string, params any) (json.RawMessage, error)
	// Notify sends a fire-and-forget notification.
	Notify(method string, params any) error
	// Notifications yields server-initiated messages (e.g. list_changed).
	Notifications() <-chan *Message
	// Close shuts the connection down.
	Close() error
}

// pendingCalls correlates responses to requests by id for the stream-based
// transports (stdio, ws, legacy sse) that share one read loop.
type pendingCalls struct {
	next    atomic.Int64
	waiters sync.Map // id string -> chan *Message
}

func (p *pendingCalls) newID() (string, json.RawMessage, chan *Message) {
	id := strconv.FormatInt(p.next.Add(1), 10)
	raw := json.RawMessage(strconv.Quote(id))
	ch := make(chan *Message, 1)
	p.waiters.Store(string(raw), ch)
	return id, raw, ch
}

func (p *pendingCalls) deliver(m *Message) bool {
	if ch, ok := p.waiters.LoadAndDelete(string(m.ID)); ok {
		ch.(chan *Message) <- m
		return true
	}
	return false
}

func (p *pendingCalls) cancel(raw json.RawMessage) { p.waiters.Delete(string(raw)) }

func marshalParams(params any) (json.RawMessage, error) {
	if params == nil {
		return nil, nil
	}
	b, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return b, nil
}
