package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// reply builds a JSON-RPC result for a request read from body.
func replyFor(body []byte, result any) []byte {
	var req Message
	_ = json.Unmarshal(body, &req)
	rb, _ := json.Marshal(result)
	out, _ := json.Marshal(Message{JSONRPC: "2.0", ID: req.ID, Result: rb})
	return out
}

func readBody(r *http.Request) []byte {
	b, _ := io.ReadAll(r.Body)
	return b
}

// --- Streamable HTTP ---

func TestHTTPTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		var req Message
		_ = json.Unmarshal(body, &req)
		if req.Method == "" { // a notification
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Mcp-Session-Id", "sess-1")
		if req.Method == "tools/list" {
			// respond via SSE to exercise that path
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", replyFor(body, map[string]any{"tools": []map[string]string{{"name": "ping"}}}))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(replyFor(body, map[string]any{"ok": true}))
	}))
	defer srv.Close()

	tr, err := startHTTP(context.Background(), "h", ServerSpec{URL: srv.URL, Type: "http"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if _, err := tr.Call(context.Background(), "initialize", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	res, err := tr.Call(context.Background(), "tools/list", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if string(res) == "" || !containsJSON(res, "ping") {
		t.Fatalf("tools/list via SSE failed: %s", res)
	}
	// session id captured from the first response
	if ht := tr.(*httpTransport); ht.sessionID != "sess-1" {
		t.Fatalf("session id not captured: %q", ht.sessionID)
	}
}

// --- Legacy HTTP+SSE ---

func TestSSETransport(t *testing.T) {
	mux := http.NewServeMux()
	var postPath = "/rpc"
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		fl, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", postPath)
		fl.Flush()
		<-r.Context().Done() // keep stream open
	})
	// responses are pushed back on the SSE stream, so we need a shared channel
	events := make(chan string, 8)
	go func() {}()
	mux.HandleFunc(postPath, func(w http.ResponseWriter, r *http.Request) {
		body := readBody(r)
		var req Message
		_ = json.Unmarshal(body, &req)
		w.WriteHeader(http.StatusAccepted)
		if req.Method != "" && len(req.ID) > 0 {
			events <- string(replyFor(body, map[string]any{"echo": req.Method}))
		}
	})
	// Rebind /sse to also drain events onto the stream.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == postPath {
			mux.ServeHTTP(w, r)
			return
		}
		fl := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", postPath)
		fl.Flush()
		for {
			select {
			case ev := <-events:
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", ev)
				fl.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer srv.Close()

	tr, err := startSSE(context.Background(), "s", ServerSpec{URL: srv.URL + "/sse", Type: "sse"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	res, err := tr.Call(context.Background(), "tools/list", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !containsJSON(res, "tools/list") {
		t.Fatalf("sse call failed: %s", res)
	}
}

// --- WebSocket ---

func TestWSTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"mcp"}})
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		for {
			_, data, err := c.Read(context.Background())
			if err != nil {
				return
			}
			var req Message
			_ = json.Unmarshal(data, &req)
			if req.Method == "" || len(req.ID) == 0 {
				continue
			}
			c.Write(context.Background(), websocket.MessageText, replyFor(data, map[string]any{"echo": req.Method}))
		}
	}))
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]

	tr, err := startWS(context.Background(), "w", ServerSpec{URL: wsURL, Type: "ws"})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := tr.Call(ctx, "tools/call", map[string]any{"name": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsJSON(res, "tools/call") {
		t.Fatalf("ws call failed: %s", res)
	}
}

func containsJSON(raw json.RawMessage, want string) bool {
	return len(raw) > 0 && json.Valid(raw) && contains(string(raw), want)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
