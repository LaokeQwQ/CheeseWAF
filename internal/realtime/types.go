// Package realtime defines interfaces for real-time communication
// between the backend and frontend (WebSocket / SSE fallback).
package realtime

import "context"

// MessageType represents the type of real-time message.
// Realtime message type.
type MessageType string

const (
	// MsgStats is a periodic statistics update.
	MsgStats MessageType = "stats"
	// MsgAlert is an attack/system alert.
	MsgAlert MessageType = "alert"
	// MsgAIStream is AI assistant streaming output.
	MsgAIStream MessageType = "ai_stream"
	// MsgApproval is a sensitive operation approval request.
	MsgApproval MessageType = "approval"
	// MsgLog is a real-time log entry.
	MsgLog MessageType = "log"
)

// Message represents a real-time message to be sent to the client.
// Realtime message sent to a client.
type Message struct {
	Type    MessageType `json:"type"`
	Payload any         `json:"payload"`
}

// ApprovalEvent invalidates clients' authorized approval views without
// exposing one request's object-scoped details on the shared realtime stream.
type ApprovalEvent struct {
	Status string `json:"status"`
}

// Transport is the interface for real-time communication channels.
// WebSocket and SSE both implement this interface.
// Realtime channel interface implemented by WebSocket and SSE.
type Transport interface {
	// Send sends a message to the client.
	// Implementations must honor context cancellation so the hub can disconnect
	// slow clients without leaking a sender goroutine.
	// Send a message to the client.
	Send(ctx context.Context, msg *Message) error

	// Receive receives a message from the client (WS only; SSE returns error).
	// Receive a message from the client (WebSocket only; SSE returns an error).
	Receive(ctx context.Context) (*Message, error)

	// Close closes the transport connection.
	// Close the connection.
	Close() error

	// Type returns the transport type ("ws" or "sse").
	// Returns the transport type.
	Type() string
}

// Notifier is the interface for sending alert notifications to external channels.
// Implementations include: Webhook, Email, Telegram, DingTalk, WeCom.
// Alert notification sender. Implementations: webhook, email, Telegram, DingTalk, WeCom.
type Notifier interface {
	// Name returns the notifier name.
	// Returns the notifier name.
	Name() string

	// Notify sends a notification.
	// Send a notification.
	Notify(ctx context.Context, title string, body string, severity string) error

	// Test sends a test notification.
	// Send a test notification.
	Test(ctx context.Context) error
}
