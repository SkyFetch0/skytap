package main

import (
	"sync"

	"github.com/SkyFetch0/gomitm"
)

type DomainState string

const (
	StateObserved    DomainState = "OBSERVED"
	StateIntercepted DomainState = "INTERCEPTED"
	StateMocked      DomainState = "MOCKED"
)

type DomainInfo struct {
	Host  string      `json:"host"`
	State DomainState `json:"state"`
	Hits  int64       `json:"hits"`
}

type Registry struct {
	mu     sync.Mutex
	states map[string]DomainState
	hits   map[string]int64
	flows  map[string][]gomitm.Flow
	ringN  int
}

func NewRegistry() *Registry {
	return &Registry{
		states: make(map[string]DomainState),
		hits:   make(map[string]int64),
		flows:  make(map[string][]gomitm.Flow),
		ringN:  64,
	}
}

func (r *Registry) Observe(host string) {
	if host == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.states[host]; !ok {
		r.states[host] = StateObserved
	}
	r.hits[host]++
}

func (r *Registry) State(host string) DomainState {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.states[host]
	if !ok {
		return StateObserved
	}
	return s
}

func (r *Registry) SetState(host string, s DomainState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states[host] = s
}

func (r *Registry) AddFlow(f gomitm.Flow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	buf := r.flows[f.Host]
	buf = append(buf, f)
	if len(buf) > r.ringN {
		buf = buf[len(buf)-r.ringN:]
	}
	r.flows[f.Host] = buf
}

func (r *Registry) Flows(host string) []gomitm.Flow {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]gomitm.Flow(nil), r.flows[host]...)
	return out
}

func (r *Registry) Domains() []DomainInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DomainInfo, 0, len(r.states))
	for h, s := range r.states {
		out = append(out, DomainInfo{Host: h, State: s, Hits: r.hits[h]})
	}
	return out
}

func (r *Registry) snapshot() map[string]DomainState {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]DomainState, len(r.states))
	for k, v := range r.states {
		m[k] = v
	}
	return m
}

func (r *Registry) loadStates(m map[string]DomainState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, v := range m {
		r.states[k] = v
	}
}

func (r *Registry) DeleteHost(host string) {
	if host == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.states, host)
	delete(r.hits, host)
	delete(r.flows, host)
}

func (r *Registry) ClearFlows(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if host == "" {
		r.flows = make(map[string][]gomitm.Flow)
		return
	}
	delete(r.flows, host)
}

func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.states = make(map[string]DomainState)
	r.hits = make(map[string]int64)
	r.flows = make(map[string][]gomitm.Flow)
}
