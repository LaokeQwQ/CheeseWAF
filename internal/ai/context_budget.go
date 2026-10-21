package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

type conversationContextKey struct{}

// ContextWithConversation adds session-bound history as ordinary user/assistant
// messages; it can never inject a system message.
func ContextWithConversation(ctx context.Context, history []Message) context.Context {
	clean := make([]Message, 0, len(history))
	for _, m := range history {
		if m.Role == "user" || m.Role == "assistant" {
			clean = append(clean, m)
		}
	}
	return context.WithValue(ctx, conversationContextKey{}, clean)
}

// prepareMessages uses a conservative token upper bound of one UTF-8 byte per
// token plus framing. This deliberately underfills models with large context
// windows instead of guessing that every language has four bytes per token.
func (c *Client) prepareMessages(ctx context.Context, messages []Message, tools []map[string]any) ([]Message, error) {
	window := c.contextWindow
	if window <= 0 {
		window = 32768
	}
	if window > maxAIContextWindow {
		window = maxAIContextWindow
	}
	reserve := c.maxTokens
	if reserve <= 0 {
		reserve = 4096
	}
	budget := window - reserve - 256
	if budget <= 0 {
		return nil, fmt.Errorf("AI context window must exceed output reserve")
	}
	if len(tools) > 0 {
		raw, err := json.Marshal(tools)
		if err != nil {
			return nil, err
		}
		budget -= len(raw) + 128
	}
	var systems, ordinary []Message
	for _, m := range messages {
		if m.Role != "system" && m.Role != "developer" && m.Role != "user" && m.Role != "assistant" && m.Role != "tool" {
			return nil, fmt.Errorf("invalid AI message role")
		}
		if m.Role == "system" {
			systems = append(systems, m)
		} else {
			ordinary = append(ordinary, m)
		}
	}
	for _, p := range c.prompts {
		if p.Enabled && (p.Model == "" || p.Model == c.model) {
			systems = append(systems, Message{Role: "system", Content: "Operator prompt " + p.ID + "@" + p.Version + ":\n" + p.Content})
		}
	}
	// Operator prompts are configuration data, not a replacement for the
	// platform safety policy. Keep an immutable boundary after them so a later
	// configured prompt cannot override the security contract.
	if len(systems) == 0 {
		systems = append(systems, Message{Role: "system", Content: aiSafetySystemPrompt})
	} else {
		systems[len(systems)-1].Content += "\n\n" + aiSafetySystemPrompt
	}
	if h, _ := ctx.Value(conversationContextKey{}).([]Message); len(h) > 0 {
		ordinary = append(append([]Message(nil), h...), ordinary...)
	}
	for _, m := range systems {
		budget -= messageBudget(m)
	}
	if budget < 64 {
		return nil, fmt.Errorf("AI system prompts and tool definitions exceed context budget")
	}
	// Keep the latest question/evidence before earlier history. All dropped
	// history has already been compressed by the bounded conversation store.
	selected := make([]Message, 0, len(ordinary))
	for i := len(ordinary) - 1; i >= 0; i-- {
		if budget <= 32 {
			break
		}
		m := ordinary[i]
		if messageBudget(m) > budget {
			if len(selected) > 0 {
				break
			}
			lo, hi := 0, len(m.Content)
			for lo < hi {
				mid := lo + (hi-lo+1)/2
				candidate := m
				candidate.Content = truncateUTF8Bytes(m.Content, mid)
				if messageBudget(candidate) <= budget {
					lo = mid
				} else {
					hi = mid - 1
				}
			}
			m.Content = truncateUTF8Bytes(m.Content, lo)
		}
		budget -= messageBudget(m)
		selected = append(selected, m)
	}
	out := append([]Message(nil), systems...)
	for i := len(selected) - 1; i >= 0; i-- {
		out = append(out, selected[i])
	}
	return out, nil
}
func messageBudget(m Message) int {
	raw, _ := json.Marshal(m)
	return len(raw) + 32
}
func truncateUTF8Bytes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return strings.TrimSpace(s[:limit])
}
