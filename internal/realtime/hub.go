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
	mu           sync.RWMutex
	clients      map[Transport]*hubClient
	queueSize    int
	sendTimeout  time.Duration
	closed       bool
	clientWG     sync.WaitGroup
	shutdownOnce sync.Once
	shutdownDone chan struct{}
}

type hubClient struct {
	transport Transport
	queue     chan *Message
	ctx       context.Context
	cancel    context.CancelFunc
	stopOnce  sync.Once
	closeOnce sync.Once
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
		clients:      make(map[Transport]*hubClient),
		queueSize:    queueSize,
		sendTimeout:  sendTimeout,
		shutdownDone: make(chan struct{}),
	}
}

func (h *Hub) Add(transport Transport) {
	if h == nil || transport == nil {
		return
	}
	queueSize := h.queueSize
	if queueSize <= 0 {
		queueSize = defaultClientQueueSize
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &hubClient{
		transport: transport,
		queue:     make(chan *Message, queueSize),
		ctx:       ctx,
		cancel:    cancel,
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		client.stop()
		return
	}
	if _, exists := h.clients[transport]; exists {
		h.mu.Unlock()
		cancel()
		return
	}
	if h.clients == nil {
		h.clients = make(map[Transport]*hubClient)
	}
	h.clients[transport] = client
	h.clientWG.Add(1)
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
	defer func() {
		client.closeTransport()
		h.clientWG.Done()
	}()
	for {
		select {
		case <-client.ctx.Done():
			return
		case msg := <-client.queue:
			timeout := h.sendTimeout
			if timeout <= 0 {
				timeout = defaultSendTimeout
			}
			ctx, cancel := context.WithTimeout(client.ctx, timeout)
			stopClose := context.AfterFunc(ctx, client.closeTransport)
			err := client.transport.Send(ctx, msg)
			ctxErr := ctx.Err()
			stopClose()
			cancel()
			if err != nil || ctxErr != nil {
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
		go c.closeTransport()
	})
}

func (c *hubClient) closeTransport() {
	c.closeOnce.Do(func() {
		_ = c.transport.Close()
	})
}

func (h *Hub) Shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	h.shutdownOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		clients := make([]*hubClient, 0, len(h.clients))
		for transport, client := range h.clients {
			clients = append(clients, client)
			delete(h.clients, transport)
		}
		if h.shutdownDone == nil {
			h.shutdownDone = make(chan struct{})
		}
		done := h.shutdownDone
		h.mu.Unlock()

		for _, client := range clients {
			client.stop()
		}
		go func() {
			h.clientWG.Wait()
			close(done)
		}()
	})

	h.mu.RLock()
	done := h.shutdownDone
	h.mu.RUnlock()
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
