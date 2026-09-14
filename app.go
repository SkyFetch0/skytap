package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/SkyFetch0/gomitm"
)

// App implements gomitm.Decider using registry + rules.
type App struct {
	reg       *Registry
	rules     *RuleEngine
	hub       *Hub
	dataDir   string
	kit       *SSLKitStore
	mu        sync.Mutex
	pinBypass bool
}

func (a *App) PinBypass() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pinBypass
}

func (a *App) SetPinBypass(v bool) {
	a.mu.Lock()
	a.pinBypass = v
	dir := a.dataDir
	a.mu.Unlock()
	if dir != "" {
		b := []byte("0\n")
		if v {
			b = []byte("1\n")
		}
		_ = os.WriteFile(filepath.Join(dir, "pin-bypass"), b, 0o644)
	}
}

func loadPinBypass(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "pin-bypass"))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

func (a *App) OnConnect(host, dst string) gomitm.Action {
	a.reg.Observe(host)
	switch a.reg.State(host) {
	case StateIntercepted, StateMocked:
		return gomitm.Terminate
	default:
		return gomitm.Passthrough
	}
}

func (a *App) OnRequest(host string, req *http.Request) *http.Response {
	st := a.reg.State(host)
	r := a.rules.matchRule(host, req)
	if r != nil && strings.EqualFold(r.Action, "rewrite") {
		if st == StateIntercepted || st == StateMocked {
			applyRewrite(req, r)
		}
		return nil // still hit the real upstream
	}
	if st != StateMocked {
		return nil
	}
	return a.rules.Match(host, req)
}

func (a *App) OnFlow(f gomitm.Flow) {
	a.reg.AddFlow(f)
	if a.hub != nil {
		a.hub.Publish(f)
	}
}
