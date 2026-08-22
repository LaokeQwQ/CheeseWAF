package realtime

import (
	"context"
	"sync"
	"time"
)

const (
	defaultClientQueueSize = 32
	defaultSendTimeout     = 5 * time.Second
)

type Hub struct {
	mu          sync.RWMutex
	clients     map[Transport]*hubClient
	queueSize   int
	sendTimeout time.Duration
}

type hubClient struct {
	transport Transport
	queue     chan *Message
	ctx       context.Context
	cancel    context.CancelFunc
	stopOnce  sync.Once
}

func NewHub() *Hub {
	return newHub(defaultClientQueueSize, defaultSendTimeout)
}

func newHub(queueSize int, sendTimeout time.Duration) *Hub {
	if queueSize <= 0 {
		queueSize = defaultClientQueueSize
	}
	if sendTimeout <= 0 {
		sendTimeout = defaultSendTimeout
	}
	return &Hub{
		clients:     make(map[Transport]*hubClient),
		queueSize:   queueSize,
		sendTimeout: sendTimeout,
	}
}

func (h *Hub) Add(transport Transport) {
	if h == nil || transport == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &hubClient{
		transport: transport,
		queue:     make(chan *Message, h.queueSize),
		ctx:       ctx,
		cancel:    cancel,
	}
	h.mu.Lock()
	if _, exists := h.clients[transport]; exists {
		h.mu.Unlock()
		cancel()
		return
	}
	h.clients[transport] = client
	h.mu.Unlock()
	go h.sendLoop(client)
}

func (h *Hub) Remove(transport Transport) {
	if h == nil || transport == nil {
		return
	}
	h.mu.Lock()
	client := h.clients[transport]
	if client != nil {
		delete(h.clients, transport)
	}
	h.mu.Unlock()
	if client != nil {
		client.stop()
	}
}

func (h *Hub) Broadcast(ctx context.Context, msg *Message) {
	if h == nil || msg == nil {
		return
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	h.mu.RLock()
	clients := make([]*hubClient, 0, len(h.clients))
	for _, client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	message := *msg
	for _, client := range clients {
		select {
		case client.queue <- &message:
		case <-client.ctx.Done():
		default:
			h.removeClient(client)
		}
	}
}

func (h *Hub) sendLoop(client *hubClient) {
	defer client.closeTransport()
	for {
		select {
		case <-client.ctx.Done():
			return
		case msg := <-client.queue:
			ctx, cancel := context.WithTimeout(client.ctx, h.sendTimeout)
			err := client.transport.Send(ctx, msg)
			cancel()
			if err != nil {
				h.removeClient(client)
				return
			}
		}
	}
}

func (h *Hub) removeClient(client *hubClient) {
	if h == nil || client == nil {
		return
	}
	h.mu.Lock()
	if h.clients[client.transport] == client {
		delete(h.clients, client.transport)
	}
	h.mu.Unlock()
	client.stop()
}

func (c *hubClient) stop() {
	c.stopOnce.Do(func() {
		c.cancel()
	})
}

func (c *hubClient) closeTransport() {
	_ = c.transport.Close()
}
