package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPTools(t *testing.T) {
	dir := t.TempDir()
	reg := NewRegistry()
	rules := NewRuleEngine()
	seed(reg, rules)
	srv := httptest.NewServer(adminMux(dir, reg, rules, "", NewHub(), nil, "127.0.0.1:8080", nil))
	t.Cleanup(srv.Close)

	list := rpc(t, srv.URL+"/mcp", "tools/list", nil)
	if !bytes.Contains(list, []byte("list_domains")) {
		t.Fatalf("%s", list)
	}

	rpc(t, srv.URL+"/mcp", "tools/call", map[string]any{
		"name": "set_state",
		"arguments": map[string]any{"host": "api.test", "state": "INTERCEPTED"},
	})
	if reg.State("api.test") != StateIntercepted {
		t.Fatal(reg.State("api.test"))
	}

	rpc(t, srv.URL+"/mcp", "tools/call", map[string]any{
		"name": "add_rule",
		"arguments": map[string]any{"host": "api.test", "path": "/", "method": "GET", "body": "x", "status": 200},
	})
	if len(rules.All()) < 2 {
		t.Fatalf("rules=%d", len(rules.All()))
	}

	out := rpc(t, srv.URL+"/mcp", "tools/call", map[string]any{
		"name": "list_domains", "arguments": map[string]any{},
	})
	if !bytes.Contains(out, []byte("check.spy.net")) {
		t.Fatalf("%s", out)
	}
}

func rpc(t *testing.T, url, method string, params any) []byte {
	t.Helper()
	payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%s", buf.Bytes())
	}
	return buf.Bytes()
}
