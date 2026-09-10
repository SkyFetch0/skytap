package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMatchSkipsRewriteForMockPath(t *testing.T) {
	e := NewRuleEngine()
	e.Add(Rule{Host: "h", Path: "/x", Method: "POST", Action: "rewrite", RewriteJSON: map[string]string{"a": "1"}})
	req, _ := http.NewRequest("POST", "http://h/x", strings.NewReader(`{}`))
	if e.Match("h", req) != nil {
		t.Fatal("rewrite must not produce a mock response")
	}
}

func TestApplyRewriteEmptyBody(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://h/x", nil)
	applyRewrite(req, &Rule{RewriteJSON: map[string]string{"domain": "test.com"}})
	b, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(b), `"domain":"test.com"`) {
		t.Fatal(string(b))
	}
}
