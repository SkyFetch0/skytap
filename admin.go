package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func adminMux(dataDir string, reg *Registry, rules *RuleEngine, token string, hub *Hub, caPEM []byte, bind string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/domains", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, reg.Domains())
	})
	mux.HandleFunc("/flows", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			var all []flowView
			for _, d := range reg.Domains() {
				all = append(all, flowViews(reg.Flows(d.Host))...)
			}
			writeJSON(w, all)
			return
		}
		writeJSON(w, flowViews(reg.Flows(host)))
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		st := DomainState(strings.ToUpper(r.URL.Query().Get("state")))
		if host == "" || st == "" {
			http.Error(w, "host and state required", 400)
			return
		}
		switch st {
		case StateObserved, StateIntercepted, StateMocked:
		default:
			http.Error(w, "state must be OBSERVED, INTERCEPTED, or MOCKED", 400)
			return
		}
		reg.SetState(host, st)
		_ = savePersist(dataDir, reg, rules)
		writeJSON(w, map[string]string{"host": host, "state": string(st)})
	})
	mux.HandleFunc("/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			id := r.URL.Query().Get("id")
			if id == "" {
				http.Error(w, "id required", 400)
				return
			}
			if !rules.Delete(id) {
				http.Error(w, "not found", 404)
				return
			}
			_ = savePersist(dataDir, reg, rules)
			writeJSON(w, map[string]any{"ok": true, "id": id})
			return
		}
		if r.Method == http.MethodPost {
			var rule Rule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			rule = rules.Add(rule)
			_ = savePersist(dataDir, reg, rules)
			writeJSON(w, rule)
			return
		}
		writeJSON(w, rules.All())
	})
	mux.HandleFunc("/mcp", mcpHandler(reg, rules, dataDir))
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="skytap-ca.pem"`)
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc("/ca/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, caStatus(caPEM, dataDir))
	})
	mux.HandleFunc("/ca/trust", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", 405)
			return
		}
		if err := installCATrust(caPEM, dataDir); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, caStatus(caPEM, dataDir))
	})
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		// Public: UI needs this before login. Never include the token itself.
		writeJSON(w, map[string]any{
			"bind":          bind,
			"loopback":      isLoopback(bind),
			"auth_required": token != "",
			"ws":            "/ws",
		})
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if hub == nil {
			http.Error(w, "no hub", 503)
			return
		}
		handleWS(w, r, hub, reg)
	})
	fs := http.FileServer(http.FS(uiFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			b, err := uiFS.ReadFile("ui/index.html")
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(b)
			return
		}
		http.StripPrefix("/", fs).ServeHTTP(w, r)
	})
	if token == "" {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/meta" || path == "/" || path == "/index.html" {
			mux.ServeHTTP(w, r)
			return
		}
		if path == "/ws" {
			q := r.URL.Query().Get("token")
			if q == "" || q != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
			return
		}
		// REST / MCP / CA: Bearer header only — never ?token= (access logs).
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
