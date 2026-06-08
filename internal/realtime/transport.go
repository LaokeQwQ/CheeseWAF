package realtime

func ConnectedMessage(transport string) *Message {
	return &Message{Type: MsgStats, Payload: map[string]any{"transport": transport, "connected": true}}
}
