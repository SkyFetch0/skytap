package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMatchSkipsRewriteForMockPath(t *testing.T) {
	e := NewRuleEngine()
	e.Add(Rule{Host: "h", Path: "/x", Method: "POST", Action: "rewrite", RewriteJSON: map[string]string{"a": "1"}})
	req, _ := http.NewRequest("POST", "http://h/x", strings.NewReader(`{}`))
	if e.Match("h", req) != nil {
		t.Fatal("rewrite must not produce a mock response")
	}
}

func TestScriptDateMarker(t *testing.T) {
	resp := renderRule(Rule{Body: `{"expires_at":"{{script: date(86400*365)}}"}`}, nil)
	b, _ := io.ReadAll(resp.Body)
	var obj map[string]string
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err, string(b))
	}
	want := time.Now().UTC().Add(365 * 24 * time.Hour).Format("2006-01-02")
	if obj["expires_at"] != want {
		t.Fatalf("expires_at %q want %q", obj["expires_at"], want)
	}
}

func TestScriptFieldOut(t *testing.T) {
	resp := renderRule(Rule{Script: `out = '{"expires_at":"' + date(0) + '"}'`}, nil)
	b, _ := io.ReadAll(resp.Body)
	var obj map[string]string
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err, string(b))
	}
	want := time.Now().UTC().Format("2006-01-02")
	if obj["expires_at"] != want {
		t.Fatalf("expires_at %q want %q", obj["expires_at"], want)
	}
}

func TestRewriteJSONPlus(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://h/x", strings.NewReader(`{}`))
	applyRewrite(req, &Rule{RewriteJSON: map[string]string{"next_check": "=plus(100)"}})
	b, _ := io.ReadAll(req.Body)
	var obj map[string]any
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal(err, string(b))
	}
	var got int64
	switch v := obj["next_check"].(type) {
	case string:
		got, _ = strconv.ParseInt(v, 10, 64)
	case float64:
		got = int64(v)
	}
	want := time.Now().Unix() + 100
	if got < want-2 || got > want+2 {
		t.Fatalf("next_check %d want ~%d", got, want)
	}
}

func TestPathTemplateStillWorks(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://h/v1", nil)
	resp := renderRule(Rule{Body: "{{path}}"}, req)
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "/v1" {
		t.Fatal(string(b))
	}
}

func TestScriptSyntaxErrorFallsBack(t *testing.T) {
	const body = `{"expires_at":"{{script: date(}}"}`
	resp := renderRule(Rule{Body: body}, nil)
	b, _ := io.ReadAll(resp.Body)
	if string(b) != body {
		t.Fatalf("got %q", string(b))
	}
}

func TestInfiniteBuiltinLoopFallsBack(t *testing.T) {
	const body = "while True:\n  now()\n"
	done := make(chan string, 1)
	go func() {
		done <- evalBody(body, true, nil)
	}()
	select {
	case got := <-done:
		if got != body {
			t.Fatalf("got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("script hung")
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
