package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"go.starlark.net/starlark"
)

type Rule struct {
	ID     string `json:"id,omitempty"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Type   string `json:"content_type"`
	// Action: "mock" (default) short-circuits; "rewrite" mutates the request then forwards upstream.
	Action string `json:"action,omitempty"`
	// RewriteJSON merges these keys into a JSON object body (e.g. {"domain":"test.com"}).
	RewriteJSON map[string]string `json:"rewrite_json,omitempty"`
	// RewriteBody replaces the entire request body (templates allowed). Overrides RewriteJSON if set.
	RewriteBody string `json:"rewrite_body,omitempty"`
	// Script is starlark; the last expression or `out` is the string used.
	Script string `json:"script,omitempty"`
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
	if r.RewriteBody != "" || r.Script != "" {
		src := r.RewriteBody
		if r.Script != "" {
			src = r.Script
		}
		body := evalBody(src, r.Script != "", req)
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
		obj[k] = evalJSONValue(v, req)
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
	src := r.Body
	whole := false
	if r.Script != "" {
		src = r.Script
		whole = true
	}
	body := evalBody(src, whole, req)
	ct := r.Type
	if ct == "" {
		ct = "application/json"
	}
	resp := &http.Response{
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", ct)
	return resp
}

var scriptMarker = regexp.MustCompile(`\{\{script:\s*(.*?)\}\}`)

// evalBody applies a whole-body starlark program when whole is set, otherwise
// replaces {{script: expr}} markers, then runs the {{path}}/{{host}} templates.
func evalBody(s string, whole bool, req *http.Request) string {
	if whole {
		if out, ok := runProgram(s, req); ok {
			s = out
		}
	} else {
		s = scriptMarker.ReplaceAllStringFunc(s, func(m string) string {
			sub := scriptMarker.FindStringSubmatch(m)
			if len(sub) < 2 {
				return m
			}
			if out, ok := evalExpr(strings.TrimSpace(sub[1]), req); ok {
				return out
			}
			return m
		})
	}
	return applyTpl(s, req)
}

// evalJSONValue treats a leading "=" as a starlark expression; otherwise a template.
func evalJSONValue(v string, req *http.Request) string {
	if strings.HasPrefix(v, "=") {
		if out, ok := evalExpr(strings.TrimSpace(v[1:]), req); ok {
			return out
		}
		return v
	}
	return evalBody(v, false, req)
}

func starlarkThread() *starlark.Thread {
	th := &starlark.Thread{Name: "rule"}
	th.SetMaxExecutionSteps(10000)
	th.SetLocal("t0", time.Now())
	return th
}

// checkScriptDeadline stops builtin-only loops that never spend execution steps.
func checkScriptDeadline(th *starlark.Thread) error {
	if th == nil {
		return nil
	}
	t0, _ := th.Local("t0").(time.Time)
	if !t0.IsZero() && time.Since(t0) > 50*time.Millisecond {
		return fmt.Errorf("script timeout")
	}
	return nil
}

func builtins(req *http.Request) starlark.StringDict {
	path, host, method := "", "", ""
	q := map[string]string{}
	if req != nil {
		if req.URL != nil {
			path = req.URL.Path
			q = queryMap(req)
		}
		host = req.Host
		method = req.Method
	}
	qm := starlark.NewDict(len(q))
	for k, v := range q {
		_ = qm.SetKey(starlark.String(k), starlark.String(v))
	}
	now := func(th *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if err := checkScriptDeadline(th); err != nil {
			return nil, err
		}
		return starlark.MakeInt64(time.Now().Unix()), nil
	}
	nowMS := func(th *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if err := checkScriptDeadline(th); err != nil {
			return nil, err
		}
		return starlark.MakeInt64(time.Now().UnixMilli()), nil
	}
	offsetOf := func(args starlark.Tuple) int64 {
		if len(args) == 0 {
			return 0
		}
		n, err := starlark.AsInt32(args[0])
		if err != nil {
			i, ok := args[0].(starlark.Int)
			if !ok {
				return 0
			}
			v, ok := i.Int64()
			if !ok {
				return 0
			}
			return v
		}
		return int64(n)
	}
	iso := func(th *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if err := checkScriptDeadline(th); err != nil {
			return nil, err
		}
		t := time.Now().UTC().Add(time.Duration(offsetOf(args)) * time.Second)
		return starlark.String(t.Format(time.RFC3339)), nil
	}
	date := func(th *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if err := checkScriptDeadline(th); err != nil {
			return nil, err
		}
		t := time.Now().UTC().Add(time.Duration(offsetOf(args)) * time.Second)
		return starlark.String(t.Format("2006-01-02")), nil
	}
	plus := func(th *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if err := checkScriptDeadline(th); err != nil {
			return nil, err
		}
		return starlark.MakeInt64(time.Now().Unix() + offsetOf(args)), nil
	}
	return starlark.StringDict{
		"now":    starlark.NewBuiltin("now", now),
		"now_ms": starlark.NewBuiltin("now_ms", nowMS),
		"iso":    starlark.NewBuiltin("iso", iso),
		"date":   starlark.NewBuiltin("date", date),
		"plus":   starlark.NewBuiltin("plus", plus),
		"path":   starlark.String(path),
		"host":   starlark.String(host),
		"method": starlark.String(method),
		"query":  qm,
	}
}

func evalExpr(src string, req *http.Request) (string, bool) {
	v, err := starlark.Eval(starlarkThread(), "expr", src, builtins(req))
	if err != nil {
		return "", false
	}
	return stringify(v), true
}

func runProgram(src string, req *http.Request) (string, bool) {
	env := builtins(req)
	g, err := starlark.ExecFile(starlarkThread(), "script", src, env)
	if err != nil {
		return "", false
	}
	if out, ok := g["out"]; ok {
		return stringify(out), true
	}
	if v, err := starlark.Eval(starlarkThread(), "expr", src, builtins(req)); err == nil {
		return stringify(v), true
	}
	return "", false
}

func stringify(v starlark.Value) string {
	switch x := v.(type) {
	case starlark.String:
		return string(x)
	case starlark.Int:
		if i, ok := x.Int64(); ok {
			return strconv.FormatInt(i, 10)
		}
		return x.String()
	case starlark.Float:
		return strconv.FormatFloat(float64(x), 'f', -1, 64)
	case starlark.Bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(v)
	}
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
