package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"text/template"
)

type Rule struct {
	ID      string `json:"id,omitempty"`
	Host    string `json:"host"`
	Path    string `json:"path"`
	Method  string `json:"method"`
	Status  int    `json:"status"`
	Body    string `json:"body"`
	Type    string `json:"content_type"`
	// Action: "mock" (default) short-circuits; "rewrite" mutates the request then forwards upstream.
	Action string `json:"action,omitempty"`
	// RewriteJSON merges these keys into a JSON object body (e.g. {"domain":"test.com"}).
	RewriteJSON map[string]string `json:"rewrite_json,omitempty"`
	// RewriteBody replaces the entire request body (templates allowed). Overrides RewriteJSON if set.
	RewriteBody string `json:"rewrite_body,omitempty"`
}

type RuleEngine struct {
	mu    sync.Mutex
	rules []Rule
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{}
}

func (e *RuleEngine) Set(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, len(rules))
	for i, r := range rules {
		if r.ID == "" {
			r.ID = newRuleID()
		}
		if r.Action == "" {
			r.Action = "mock"
		}
		out[i] = r
	}
	e.rules = out
}

func (e *RuleEngine) Add(r Rule) Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.ID == "" {
		r.ID = newRuleID()
	}
	if r.Action == "" {
		r.Action = "mock"
	}
	e.rules = append(e.rules, r)
	return r
}

func (e *RuleEngine) Delete(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.rules[:0]
	ok := false
	for _, r := range e.rules {
		if r.ID == id {
			ok = true
			continue
		}
		out = append(out, r)
	}
	e.rules = out
	return ok
}

func newRuleID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (e *RuleEngine) All() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Rule(nil), e.rules...)
}

func (e *RuleEngine) matchRule(host string, req *http.Request) *Rule {
	e.mu.Lock()
	rules := append([]Rule(nil), e.rules...)
	e.mu.Unlock()
	path := req.URL.Path
	method := req.Method
	for i := range rules {
		r := &rules[i]
		if r.Host != "" && !strings.EqualFold(r.Host, host) {
			continue
		}
		if r.Path != "" && r.Path != path && !pathMatch(r.Path, path) {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		cp := *r
		return &cp
	}
	return nil
}

func (e *RuleEngine) Match(host string, req *http.Request) *http.Response {
	r := e.matchRule(host, req)
	if r == nil || strings.EqualFold(r.Action, "rewrite") {
		return nil
	}
	return renderRule(*r, req)
}

func applyRewrite(req *http.Request, r *Rule) {
	if r.RewriteBody != "" {
		body := applyTpl(r.RewriteBody, req)
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(body)), nil
		}
		return
	}
	if len(r.RewriteJSON) == 0 {
		return
	}
	var raw []byte
	if req.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(req.Body, 1<<20))
		req.Body.Close()
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		obj = map[string]any{}
	}
	for k, v := range r.RewriteJSON {
		obj[k] = applyTpl(v, req)
	}
	out, err := json.Marshal(obj)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(out)), nil
	}
}

func pathMatch(pat, path string) bool {
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pat, "*"))
	}
	return pat == path
}

func renderRule(r Rule, req *http.Request) *http.Response {
	status := r.Status
	if status == 0 {
		status = 200
	}
	body := applyTpl(r.Body, req)
	ct := r.Type
	if ct == "" {
		ct = "application/json"
	}
	resp := &http.Response{
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", ct)
	return resp
}

func applyTpl(s string, req *http.Request) string {
	if s == "" || req == nil {
		return s
	}
	data := map[string]any{
		"path":  req.URL.Path,
		"query": queryMap(req),
		"host":  req.Host,
	}
	s = strings.NewReplacer("{{path}}", "{{.path}}", "{{host}}", "{{.host}}", "{{query.", "{{.query.").Replace(s)
	if !strings.Contains(s, "{{") {
		return s
	}
	t, err := template.New("r").Parse(s)
	if err != nil {
		return s
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return s
	}
	return buf.String()
}

func queryMap(req *http.Request) map[string]string {
	m := map[string]string{}
	for k, v := range req.URL.Query() {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}
