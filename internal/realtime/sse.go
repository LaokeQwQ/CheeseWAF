package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type SSETransport struct {
	w       http.ResponseWriter
	flusher http.Flusher
	done    <-chan struct{}
	mu      sync.Mutex
}

func (h *Hub) SSEHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	transport := &SSETransport{w: w, flusher: flusher, done: r.Context().Done()}
	if err := transport.Send(r.Context(), ConnectedMessage("sse")); err != nil {
		return
	}
	h.Add(transport)
	defer h.Remove(transport)
	<-r.Context().Done()
}

func (t *SSETransport) Send(ctx context.Context, msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return context.Canceled
	default:
	}
	deadline := time.Now().Add(defaultSendTimeout)
	if value, ok := ctx.Deadline(); ok {
		deadline = value
	}
	controller := http.NewResponseController(t.w)
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
	if _, err := fmt.Fprintf(t.w, "event: %s\ndata: %s\n\n", msg.Type, data); err != nil {
		return err
	}
	if err := controller.Flush(); err != nil {
		if !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		t.flusher.Flush()
	}
	return nil
}

func (t *SSETransport) Receive(context.Context) (*Message, error) {
	return nil, errors.New("sse transport does not support receive")
}

func (t *SSETransport) Close() error { return nil }
func (t *SSETransport) Type() string { return "sse" }
