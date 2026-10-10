package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saifety-org/sAIfety/internal/policy"
)

func TestProxyDeniesToolCallWhenBlocklistCannotBeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	bl, err := policy.LoadBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{broken`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Blocklist: bl}
	response := p.toolsCall(context.Background(), &Message{ID: json.RawMessage(`1`), Params: json.RawMessage(`{"name":"fake__echo","arguments":{}}`)})
	var result struct {
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(string(response.Result), "blocklist state unavailable") {
		t.Fatalf("call was not explicitly withheld: %s", response.Result)
	}
}
