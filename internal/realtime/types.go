// Package realtime defines interfaces for real-time communication
// between the backend and frontend (WebSocket / SSE fallback).
package realtime

import "context"

// MessageType represents the type of real-time message.
// 实时消息类型。
type MessageType string

const (
	// MsgStats is a periodic statistics update. 周期性统计数据更新。
	MsgStats MessageType = "stats"
	// MsgAlert is an attack/system alert. 攻击/系统告警。
	MsgAlert MessageType = "alert"
	// MsgAIStream is AI assistant streaming output. AI 助手流式输出。
	MsgAIStream MessageType = "ai_stream"
	// MsgApproval is a sensitive operation approval request. 敏感操作审批请求。
	MsgApproval MessageType = "approval"
	// MsgLog is a real-time log entry. 实时日志条目。
	MsgLog MessageType = "log"
)

// Message represents a real-time message to be sent to the client.
// 发送给客户端的实时消息。
type Message struct {
	Type    MessageType `json:"type"`
	Payload any         `json:"payload"`
}

// Transport is the interface for real-time communication channels.
// WebSocket and SSE both implement this interface.
// 实时通信通道接口，WebSocket 和 SSE 都实现此接口。
type Transport interface {
	// Send sends a message to the client.
	// 向客户端发送消息。
	Send(ctx context.Context, msg *Message) error

	// Receive receives a message from the client (WS only; SSE returns error).
	// 从客户端接收消息（仅 WS 支持；SSE 返回错误）。
	Receive(ctx context.Context) (*Message, error)

	// Close closes the transport connection.
	// 关闭连接。
	Close() error

	// Type returns the transport type ("ws" or "sse").
	// 返回传输类型。
	Type() string
}

// Notifier is the interface for sending alert notifications to external channels.
// Implementations include: Webhook, Email, Telegram, DingTalk, WeCom.
// 告警通知发送接口。实现包括：Webhook、邮件、Telegram、钉钉、企业微信。
type Notifier interface {
	// Name returns the notifier name.
	// 返回通知器名称。
	Name() string

	// Notify sends a notification.
	// 发送通知。
	Notify(ctx context.Context, title string, body string, severity string) error

	// Test sends a test notification.
	// 发送测试通知。
	Test(ctx context.Context) error
}
