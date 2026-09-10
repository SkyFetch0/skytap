package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRewriteJSONDomain(t *testing.T) {
	reg := NewRegistry()
	reg.SetState("lsn.sener.dev", StateIntercepted)
	rules := NewRuleEngine()
	rules.Add(Rule{
		Host:        "lsn.sener.dev",
		Path:        "/api/verify",
		Method:      "POST",
		Action:      "rewrite",
		RewriteJSON: map[string]string{"domain": "test.com"},
	})
	app := &App{reg: reg, rules: rules}
	req, _ := http.NewRequest("POST", "http://lsn.sener.dev/api/verify", strings.NewReader(`{"license_key":"1234","domain":"example.com"}`))
	req.Host = "lsn.sener.dev"
	req.Header.Set("Content-Type", "application/json")
	if app.OnRequest("lsn.sener.dev", req) != nil {
		t.Fatal("rewrite must not mock")
	}
	b, _ := io.ReadAll(req.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["domain"] != "test.com" {
		t.Fatalf("domain=%v body=%s", m["domain"], b)
	}
	if m["license_key"] != "1234" {
		t.Fatalf("key lost: %s", b)
	}
}
