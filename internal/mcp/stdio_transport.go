package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// stdioTransport speaks JSON-RPC over a child process's stdin/stdout, the
// default MCP transport. One read loop dispatches responses and notifications.
type stdioTransport struct {
	cmd     *exec.Cmd
	conn    *Conn
	pending pendingCalls
	notes   chan *Message
	done    chan struct{}
	err     error
}

func startStdio(ctx context.Context, name string, spec ServerSpec, stderr io.Writer) (transport, error) {
	cmd := exec.CommandContext(ctx, spec.Command, spec.Args...)
	cmd.Env = os.Environ()
	for k, v := range spec.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%s: start: %w", name, err)
	}
	t := &stdioTransport{
		cmd:   cmd,
		conn:  NewConn(stdout, stdin),
		notes: make(chan *Message, 64),
		done:  make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

func (t *stdioTransport) readLoop() {
	defer close(t.done)
	defer close(t.notes)
	for {
		m, err := t.conn.Read()
		if m != nil {
			dispatch(m, &t.pending, t.notes, t.conn)
		}
		if err != nil {
			t.err = err
			return
		}
	}
}

func (t *stdioTransport) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	p, err := marshalParams(params)
	if err != nil {
		return nil, err
	}
	id, raw, ch := t.pending.newID()
	_ = id
	if err := t.conn.Write(&Message{ID: raw, Method: method, Params: p}); err != nil {
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
		return nil, fmt.Errorf("connection closed: %v", t.err)
	}
}

func (t *stdioTransport) Notify(method string, params any) error {
	p, err := marshalParams(params)
	if err != nil {
		return err
	}
	return t.conn.Write(&Message{Method: method, Params: p})
}

func (t *stdioTransport) Notifications() <-chan *Message { return t.notes }

func (t *stdioTransport) Close() error {
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
	return t.cmd.Wait()
}

// dispatch routes an incoming message: responses go to their waiter,
// notifications to the notes channel, and server->client requests get a
// polite "not supported" so the server isn't left waiting.
func dispatch(m *Message, pending *pendingCalls, notes chan<- *Message, replyTo *Conn) {
	switch {
	case m.IsResponse():
		pending.deliver(m)
	case m.IsNotification():
		select {
		case notes <- m:
		default:
		}
	case m.IsRequest():
		if replyTo != nil {
			_ = replyTo.Write(Fail(m, CodeMethodNotFound, "not supported by saifety proxy"))
		}
	}
}
