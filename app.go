package main

import (
	"net/http"
	"strings"

	"github.com/SkyFetch0/gomitm"
)

// App implements gomitm.Decider using registry + rules.
type App struct {
	reg   *Registry
	rules *RuleEngine
	hub   *Hub
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
