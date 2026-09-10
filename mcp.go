package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/SkyFetch0/gomitm"
)

type flowView struct {
	Time         time.Time `json:"time"`
	Host         string    `json:"host"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	Status       int       `json:"status"`
	ReqSize      int64     `json:"req_size"`
	ResSize      int64     `json:"res_size"`
	Mocked       bool      `json:"mocked"`
	ReqBody      string    `json:"req_body,omitempty"`
	ResBody      string    `json:"res_body,omitempty"`
	ReqEncoding  string    `json:"req_encoding,omitempty"` // utf8 | base64
	ResEncoding  string    `json:"res_encoding,omitempty"`
	ReqTruncated bool      `json:"req_truncated,omitempty"`
	ResTruncated bool      `json:"res_truncated,omitempty"`
}

func encodeBody(b []byte) (s, enc string) {
	if len(b) == 0 {
		return "", ""
	}
	if utf8.Valid(b) && !bytesLookBinary(b) {
		return string(b), "utf8"
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func bytesLookBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

func flowViews(in []gomitm.Flow) []flowView {
	out := make([]flowView, 0, len(in))
	for _, f := range in {
		reqS, reqE := encodeBody(f.ReqBody)
		resS, resE := encodeBody(f.ResBody)
		out = append(out, flowView{
			Time: f.Time, Host: f.Host, Method: f.Method, Path: f.Path,
			Status: f.Status, ReqSize: f.ReqSize, ResSize: f.ResSize, Mocked: f.Mocked,
			ReqBody: reqS, ResBody: resS, ReqEncoding: reqE, ResEncoding: resE,
			ReqTruncated: f.ReqTruncated, ResTruncated: f.ResTruncated,
		})
	}
	return out
}

// Minimal MCP JSON-RPC 2.0 over HTTP POST /mcp (and optional stdio).
// Tools wrap the same registry + rules as the admin API.

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResp struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   *rpcErr `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func mcpHandler(reg *Registry, rules *RuleEngine, dataDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		out := handleRPC(reg, rules, dataDir, body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	}
}

func handleRPC(reg *Registry, rules *RuleEngine, dataDir string, raw []byte) []byte {
	var req rpcReq
	if err := json.Unmarshal(raw, &req); err != nil {
		b, _ := json.Marshal(rpcResp{JSONRPC: "2.0", Error: &rpcErr{Code: -32700, Message: err.Error()}})
		return b
	}
	res := rpcResp{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		res.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "skytap", "version": "0.1.0"},
		}
	case "notifications/initialized", "ping":
		res.Result = map[string]any{}
	case "tools/list":
		res.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		var tc toolCall
		if err := json.Unmarshal(req.Params, &tc); err != nil {
			res.Error = &rpcErr{Code: -32602, Message: err.Error()}
			break
		}
		text, err := callTool(reg, rules, dataDir, tc.Name, tc.Arguments)
		if err != nil {
			res.Error = &rpcErr{Code: -32000, Message: err.Error()}
			break
		}
		res.Result = map[string]any{
			"content": []map[string]string{{"type": "text", "text": text}},
		}
	default:
		res.Error = &rpcErr{Code: -32601, Message: "method not found"}
	}
	b, _ := json.Marshal(res)
	return b
}

func mcpTools() []map[string]any {
	return []map[string]any{
		{"name": "list_domains", "description": "List observed domains and states", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "set_state", "description": "Set domain state OBSERVED|INTERCEPTED|MOCKED", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"host": map[string]any{"type": "string"}, "state": map[string]any{"type": "string"},
		}, "required": []string{"host", "state"}}},
		{"name": "add_rule", "description": "Add mock rule (host+path+method -> body)", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"host": map[string]any{"type": "string"}, "path": map[string]any{"type": "string"}, "method": map[string]any{"type": "string"},
			"status": map[string]any{"type": "integer"}, "body": map[string]any{"type": "string"}, "content_type": map[string]any{"type": "string"},
		}, "required": []string{"host"}}},
		{"name": "get_flows", "description": "Recent flows for a host including capped bodies", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{
			"host": map[string]any{"type": "string"},
		}, "required": []string{"host"}}},
	}
}

func callTool(reg *Registry, rules *RuleEngine, dataDir, name string, args json.RawMessage) (string, error) {
	var m map[string]any
	if len(args) > 0 {
		_ = json.Unmarshal(args, &m)
	}
	if m == nil {
		m = map[string]any{}
	}
	str := func(k string) string {
		v, _ := m[k].(string)
		return v
	}
	switch name {
	case "list_domains":
		b, err := json.MarshalIndent(reg.Domains(), "", "  ")
		return string(b), err
	case "set_state":
		st := DomainState(strings.ToUpper(str("state")))
		reg.SetState(str("host"), st)
		_ = savePersist(dataDir, reg, rules)
		b, err := json.Marshal(map[string]string{"host": str("host"), "state": string(st)})
		return string(b), err
	case "add_rule":
		r := Rule{Host: str("host"), Path: str("path"), Method: str("method"), Body: str("body"), Type: str("content_type")}
		if n, ok := m["status"].(float64); ok {
			r.Status = int(n)
		}
		rules.Add(r)
		_ = savePersist(dataDir, reg, rules)
		b, err := json.Marshal(r)
		return string(b), err
	case "get_flows":
		b, err := json.MarshalIndent(flowViews(reg.Flows(str("host"))), "", "  ")
		return string(b), err
	default:
		return "", os.ErrInvalid
	}
}
