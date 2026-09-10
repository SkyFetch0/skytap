package main

import (
	"encoding/json"
	"sync"

	"github.com/SkyFetch0/gomitm"
)

// Hub fans OnFlow out to WebSocket clients. Does not replace the registry ring.
type Hub struct {
	mu      sync.Mutex
	clients map[*wsConn]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*wsConn]struct{})}
}

func (h *Hub) add(c *wsConn) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) remove(c *wsConn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (h *Hub) Publish(f gomitm.Flow) {
	if h == nil {
		return
	}
	views := flowViews([]gomitm.Flow{f})
	b, err := json.Marshal(map[string]any{"type": "flow", "flow": views[0]})
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		c.send(b)
	}
}
