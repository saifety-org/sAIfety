package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Upstream is a client connection to one real MCP server. The concrete
// transport is chosen from the server spec: stdio for a command, or
// http/ws/sse for a url.
type Upstream struct {
	Name string
	Spec ServerSpec

	t            transport
	ServerInfo   json.RawMessage
	Capabilities json.RawMessage
}

// Start connects to the server described by spec. For stdio servers it
// launches the process; for url servers it opens the matching transport.
func Start(ctx context.Context, name string, spec ServerSpec, stderr io.Writer) (*Upstream, error) {
	var (
		t   transport
		err error
	)
	switch {
	case spec.URL != "":
		t, err = startRemote(ctx, name, spec)
	case spec.Command != "":
		t, err = startStdio(ctx, name, spec, stderr)
	default:
		return nil, fmt.Errorf("%s: server has neither command nor url", name)
	}
	if err != nil {
		return nil, err
	}
	return &Upstream{Name: name, Spec: spec, t: t}, nil
}

// startRemote picks the transport for a url-based server. The MCP transport
// type comes from spec.Type; when absent we default to streamable HTTP for
// http(s) urls and WebSocket for ws(s) urls.
func startRemote(ctx context.Context, name string, spec ServerSpec) (transport, error) {
	typ := strings.ToLower(spec.Type)
	if typ == "" {
		switch {
		case strings.HasPrefix(spec.URL, "ws"):
			typ = "ws"
		default:
			typ = "http"
		}
	}
	switch typ {
	case "http", "streamable-http", "streamable_http":
		return startHTTP(ctx, name, spec)
	case "sse":
		return startSSE(ctx, name, spec)
	case "ws", "websocket":
		return startWS(ctx, name, spec)
	default:
		return nil, fmt.Errorf("%s: unsupported transport %q", name, spec.Type)
	}
}

// Call sends a request and waits for its response.
func (u *Upstream) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return u.t.Call(ctx, method, params)
}

// Notify sends a notification.
func (u *Upstream) Notify(method string, params any) error {
	return u.t.Notify(method, params)
}

// Notifications yields server-initiated messages.
func (u *Upstream) Notifications() <-chan *Message { return u.t.Notifications() }

// Initialize performs the MCP handshake on behalf of the proxy.
func (u *Upstream) Initialize(ctx context.Context, protocolVersion string, clientInfo json.RawMessage) error {
	res, err := u.Call(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      clientInfo,
	})
	if err != nil {
		return fmt.Errorf("%s: initialize: %w", u.Name, err)
	}
	var init struct {
		ServerInfo   json.RawMessage `json:"serverInfo"`
		Capabilities json.RawMessage `json:"capabilities"`
	}
	_ = json.Unmarshal(res, &init)
	u.ServerInfo, u.Capabilities = init.ServerInfo, init.Capabilities
	return u.Notify("notifications/initialized", nil)
}

// Close terminates the connection.
func (u *Upstream) Close() error { return u.t.Close() }
