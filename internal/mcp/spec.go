// Package mcp implements the Model Context Protocol machinery the proxy
// needs: JSON-RPC 2.0 framing, upstream clients over every MCP transport
// (stdio, streamable HTTP, legacy HTTP+SSE, WebSocket), and the aggregating
// proxy itself. It is written against the protocol directly rather than an
// SDK so that every message can be intercepted and rewritten.
package mcp

// ServerSpec describes how to reach an upstream server. Field names match
// Claude Code's .mcp.json / Claude Desktop's config.
type ServerSpec struct {
	// Type is the MCP transport: "stdio" (default for a command), or
	// "http" / "sse" / "ws" for a url. Empty is inferred from the fields.
	Type string `json:"type,omitempty"`
	// stdio transport.
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	// Remote transports (http/sse/ws).
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}
