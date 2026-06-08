package realtime

import (
	"context"
	"sync"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[Transport]struct{}
}

func NewHub() *Hub {
	return &Hub{clients: map[Transport]struct{}{}}
}

func (h *Hub) Add(transport Transport) {
	h.mu.Lock()
	h.clients[transport] = struct{}{}
	h.mu.Unlock()
}

func (h *Hub) Remove(transport Transport) {
	h.mu.Lock()
	delete(h.clients, transport)
	h.mu.Unlock()
	_ = transport.Close()
}

func (h *Hub) Broadcast(ctx context.Context, msg *Message) {
	h.mu.RLock()
	clients := make([]Transport, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		if err := client.Send(ctx, msg); err != nil {
			h.Remove(client)
		}
	}
}
