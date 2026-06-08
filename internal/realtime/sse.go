package realtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type SSETransport struct {
	w       http.ResponseWriter
	flusher http.Flusher
	done    <-chan struct{}
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
	h.Add(transport)
	defer h.Remove(transport)
	_ = transport.Send(r.Context(), &Message{Type: MsgStats, Payload: map[string]any{"connected": true}})
	<-r.Context().Done()
}

func (t *SSETransport) Send(_ context.Context, msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(t.w, "event: %s\ndata: %s\n\n", msg.Type, data); err != nil {
		return err
	}
	t.flusher.Flush()
	return nil
}

func (t *SSETransport) Receive(context.Context) (*Message, error) {
	return nil, errors.New("sse transport does not support receive")
}

func (t *SSETransport) Close() error { return nil }
func (t *SSETransport) Type() string { return "sse" }
