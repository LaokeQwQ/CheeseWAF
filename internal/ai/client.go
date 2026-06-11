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
		httpClient = &http.Client{Timeout: 120 * time.Second}
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

func (c *Client) CompleteToolPlan(ctx context.Context, messages []Message, tools []map[string]any) (*AssistantPlan, error) {
	if c == nil {
		return nil, fmt.Errorf("ai client is nil")
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("tool definitions are required")
	}
	switch c.provider {
	case "openai":
		return c.completeOpenAIToolPlan(ctx, messages, tools)
	case "anthropic":
		return c.completeAnthropicToolPlan(ctx, messages, tools)
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

func (c *Client) completeOpenAIToolPlan(ctx context.Context, messages []Message, tools []map[string]any) (*AssistantPlan, error) {
	payload := chatRequest{Model: c.model, Messages: messages, Temperature: 0.2, Tools: tools, ToolChoice: "auto"}
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
	message := parsed.Choices[0].Message
	plan := parseAssistantPlan(message.Content)
	if len(message.ToolCalls) > 0 {
		plan.ToolRequests = plan.ToolRequests[:0]
		for _, call := range message.ToolCalls {
			args := map[string]any{}
			if strings.TrimSpace(call.Function.Arguments) != "" {
				decoder := json.NewDecoder(strings.NewReader(call.Function.Arguments))
				decoder.UseNumber()
				if err := decoder.Decode(&args); err != nil {
					return nil, fmt.Errorf("decode tool arguments for %s: %w", call.Function.Name, err)
				}
			}
			plan.ToolRequests = append(plan.ToolRequests, AssistantToolRequest{Name: call.Function.Name, Args: args})
		}
		plan.Answer = strings.TrimSpace(message.Content)
		plan.Mode = "native_openai_tool_calls"
	} else if plan.Mode == "" {
		plan.Mode = "native_openai_no_tool_call"
	}
	plan.Provider = c.provider
	plan.Model = c.model
	plan.InputTokens = parsed.Usage.PromptTokens
	plan.OutputTokens = parsed.Usage.CompletionTokens
	plan.TotalTokens = parsed.Usage.TotalTokens
	return plan, nil
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

func (c *Client) completeAnthropicToolPlan(ctx context.Context, messages []Message, tools []map[string]any) (*AssistantPlan, error) {
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
		Tools:       anthropicTools(tools),
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
	var requests []AssistantToolRequest
	for _, block := range parsed.Content {
		switch block.Type {
		case "tool_use":
			requests = append(requests, AssistantToolRequest{Name: block.Name, Args: block.Input})
		default:
			if strings.TrimSpace(block.Text) != "" {
				parts = append(parts, strings.TrimSpace(block.Text))
			}
		}
	}
	plan := parseAssistantPlan(strings.Join(parts, "\n"))
	if len(requests) > 0 {
		plan.ToolRequests = requests
		plan.Mode = "native_anthropic_tool_use"
	} else if plan.Mode == "" {
		plan.Mode = "native_anthropic_no_tool_use"
	}
	plan.Provider = c.provider
	plan.Model = c.model
	plan.InputTokens = parsed.Usage.InputTokens
	plan.OutputTokens = parsed.Usage.OutputTokens
	plan.TotalTokens = parsed.Usage.InputTokens + parsed.Usage.OutputTokens
	return plan, nil
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
	Model       string           `json:"model"`
	Messages    []Message        `json:"messages"`
	Temperature float64          `json:"temperature"`
	Tools       []map[string]any `json:"tools,omitempty"`
	ToolChoice  any              `json:"tool_choice,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message chatResponseMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type chatResponseMessage struct {
	Role      string         `json:"role"`
	Content   string         `json:"content"`
	ToolCalls []chatToolCall `json:"tool_calls"`
}

type chatToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	Tools       []anthropicTool    `json:"tools,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type  string         `json:"type"`
		Text  string         `json:"text"`
		ID    string         `json:"id"`
		Name  string         `json:"name"`
		Input map[string]any `json:"input"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

func anthropicTools(tools []map[string]any) []anthropicTool {
	out := make([]anthropicTool, 0, len(tools))
	for _, tool := range tools {
		fn, _ := tool["function"].(map[string]any)
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		if strings.TrimSpace(name) == "" {
			continue
		}
		description, _ := fn["description"].(string)
		schema, _ := fn["parameters"].(map[string]any)
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, anthropicTool{Name: name, Description: description, InputSchema: schema})
	}
	return out
}
