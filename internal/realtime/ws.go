package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"nhooyr.io/websocket"
)

type WebSocketTransport struct {
	conn *websocket.Conn
}

func (h *Hub) WSHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	transport := &WebSocketTransport{conn: conn}
	h.Add(transport)
	defer h.Remove(transport)
	_ = transport.Send(r.Context(), &Message{Type: MsgStats, Payload: map[string]any{"connected": true}})
	for {
		if _, err := transport.Receive(r.Context()); err != nil {
			return
		}
	}
}

func (t *WebSocketTransport) Send(ctx context.Context, msg *Message) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return t.conn.Write(ctx, websocket.MessageText, data)
}

func (t *WebSocketTransport) Receive(ctx context.Context) (*Message, error) {
	_, data, err := t.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (t *WebSocketTransport) Close() error {
	return t.conn.Close(websocket.StatusNormalClosure, "closed")
}

func (t *WebSocketTransport) Type() string { return "ws" }
