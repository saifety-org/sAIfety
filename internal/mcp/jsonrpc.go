package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Message is a JSON-RPC 2.0 request, notification or response. MCP uses all
// three over one channel, so a single struct with optional fields is simplest.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent for notifications
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc %d: %s", e.Code, e.Message) }

// Standard error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// IsRequest reports whether m expects a response.
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports whether m is a notification.
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// IsResponse reports whether m answers a request.
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// Conn is a newline-delimited JSON channel (the MCP stdio transport).
// Writes are serialized; reads are expected from a single goroutine.
type Conn struct {
	r  *bufio.Reader
	w  io.Writer
	mu sync.Mutex
}

// NewConn wraps a reader/writer pair.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 1<<20), w: w}
}

// Read blocks for the next message. io.EOF means the peer closed.
func (c *Conn) Read() (*Message, error) {
	for {
		line, err := c.r.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return nil, err
		}
		if len(trimSpace(line)) == 0 {
			if err != nil {
				return nil, err
			}
			continue
		}
		var m Message
		if jerr := json.Unmarshal(line, &m); jerr != nil {
			return nil, fmt.Errorf("parse: %w", jerr)
		}
		return &m, err
	}
}

// Write sends one message followed by a newline.
func (c *Conn) Write(m *Message) error {
	if m.JSONRPC == "" {
		m.JSONRPC = "2.0"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.w.Write(append(b, '\n'))
	return err
}

// Reply builds a successful response to req.
func Reply(req *Message, result any) *Message {
	b, _ := json.Marshal(result)
	return &Message{JSONRPC: "2.0", ID: req.ID, Result: b}
}

// Fail builds an error response to req.
func Fail(req *Message, code int, msg string) *Message {
	return &Message{JSONRPC: "2.0", ID: req.ID, Error: &RPCError{Code: code, Message: msg}}
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\r' || b[j-1] == '\n') {
		j--
	}
	return b[i:j]
}
