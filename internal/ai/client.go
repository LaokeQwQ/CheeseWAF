package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type CompletionResult struct {
	Content  string          `json:"content"`
	Provider string          `json:"provider"`
	Model    string          `json:"model"`
	Usage    CompletionUsage `json:"usage"`
}

type CompletionUsage struct {
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`
	TotalTokens  int `json:"total_tokens,omitempty"`
}

type Client struct {
	provider string
	apiBase  string
	apiKey   string
	model    string
	http     *http.Client
}

func NewClient(cfg config.AIConfig, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	provider := normalizeProvider(cfg.Provider)
	return &Client{
		provider: provider,
		apiBase:  strings.TrimRight(defaultAPIBase(provider, cfg.APIBase), "/"),
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		http:     httpClient,
	}
}

func (c *Client) Complete(ctx context.Context, messages []Message) (string, error) {
	result, err := c.CompleteWithUsage(ctx, messages)
	if err != nil {
		return "", err
	}
	return result.Content, nil
}

func (c *Client) CompleteWithUsage(ctx context.Context, messages []Message) (*CompletionResult, error) {
	if c == nil {
		return nil, fmt.Errorf("ai client is nil")
	}
	if c.apiBase == "" {
		return nil, fmt.Errorf("ai api_base is required")
	}
	if c.model == "" {
		return nil, fmt.Errorf("ai model is required")
	}
	switch c.provider {
	case "openai":
		return c.completeOpenAI(ctx, messages)
	case "anthropic":
		return c.completeAnthropic(ctx, messages)
	default:
		return nil, fmt.Errorf("unsupported ai provider %q", c.provider)
	}
}

func (c *Client) completeOpenAI(ctx context.Context, messages []Message) (*CompletionResult, error) {
	payload := chatRequest{Model: c.model, Messages: messages, Temperature: 0.2}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ai api returned %s", resp.Status)
	}
	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("ai api returned no choices")
	}
	return &CompletionResult{
		Content:  strings.TrimSpace(parsed.Choices[0].Message.Content),
		Provider: c.provider,
		Model:    c.model,
		Usage: CompletionUsage{
			InputTokens:  parsed.Usage.PromptTokens,
			OutputTokens: parsed.Usage.CompletionTokens,
			TotalTokens:  parsed.Usage.TotalTokens,
		},
	}, nil
}

func (c *Client) completeAnthropic(ctx context.Context, messages []Message) (*CompletionResult, error) {
	system, conversation := anthropicMessages(messages)
	if len(conversation) == 0 {
		conversation = []anthropicMessage{{Role: "user", Content: "Continue."}}
	}
	payload := anthropicRequest{
		Model:       c.model,
		System:      system,
		Messages:    conversation,
		MaxTokens:   1024,
		Temperature: 0.2,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	if c.apiKey != "" {
		req.Header.Set("x-api-key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ai api returned %s", resp.Status)
	}
	var parsed anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	var parts []string
	for _, block := range parsed.Content {
		if strings.TrimSpace(block.Text) != "" {
			parts = append(parts, strings.TrimSpace(block.Text))
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("ai api returned no content")
	}
	return &CompletionResult{
		Content:  strings.Join(parts, "\n"),
		Provider: c.provider,
		Model:    c.model,
		Usage: CompletionUsage{
			InputTokens:  parsed.Usage.InputTokens,
			OutputTokens: parsed.Usage.OutputTokens,
			TotalTokens:  parsed.Usage.InputTokens + parsed.Usage.OutputTokens,
		},
	}, nil
}

func normalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "openai", "openai-compatible", "openai_compatible":
		return "openai"
	case "anthropic", "claude":
		return "anthropic"
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func defaultAPIBase(provider, apiBase string) string {
	if strings.TrimSpace(apiBase) != "" {
		return strings.TrimSpace(apiBase)
	}
	if provider == "anthropic" {
		return "https://api.anthropic.com/v1"
	}
	return "https://api.openai.com/v1"
}

func anthropicMessages(messages []Message) (string, []anthropicMessage) {
	var system []string
	var conversation []anthropicMessage
	for _, message := range messages {
		content := strings.TrimSpace(message.Content)
		if content == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(message.Role)) {
		case "system":
			system = append(system, content)
		case "assistant":
			conversation = append(conversation, anthropicMessage{Role: "assistant", Content: content})
		default:
			conversation = append(conversation, anthropicMessage{Role: "user", Content: content})
		}
	}
	return strings.Join(system, "\n\n"), conversation
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}
