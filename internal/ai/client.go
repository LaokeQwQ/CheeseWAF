package ai

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	openaisdk "github.com/openai/openai-go"
	openaioption "github.com/openai/openai-go/option"
	openaiparam "github.com/openai/openai-go/packages/param"
	openaishared "github.com/openai/openai-go/shared"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type CompletionResult struct {
	Content          string          `json:"content"`
	ReasoningSummary string          `json:"reasoning_summary,omitempty"`
	Provider         string          `json:"provider"`
	Model            string          `json:"model"`
	Usage            CompletionUsage `json:"usage"`
}

type CompletionUsage struct {
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`
	TotalTokens  int `json:"total_tokens,omitempty"`
}

type StreamEmitter func(AssistantTraceEvent)

type ModelInfo struct {
	ID      string `json:"id"`
	OwnedBy string `json:"owned_by,omitempty"`
	Created int64  `json:"created,omitempty"`
}

type Client struct {
	provider     string
	apiBase      string
	apiKey       string
	model        string
	allowPrivate bool
	http         *http.Client
	openai       openaisdk.Client
}

const defaultAIHTTPTimeout = 5 * time.Minute

func NewClient(cfg config.AIConfig, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = newAIHTTPClient(cfg, defaultAIHTTPTimeout)
	}
	provider := normalizeProvider(cfg.Provider)
	client := &Client{
		provider:     provider,
		apiBase:      strings.TrimRight(defaultAPIBase(provider, cfg.APIBase), "/"),
		apiKey:       cfg.APIKey,
		model:        cfg.Model,
		allowPrivate: cfg.AllowPrivateAPIBase,
		http:         httpClient,
	}
	if provider == "openai" {
		client.openai = newOpenAISDKClient(client.apiBase, client.apiKey, httpClient)
	}
	return client
}

func NewClientWithTimeout(cfg config.AIConfig, timeout time.Duration) *Client {
	return NewClient(cfg, newAIHTTPClient(cfg, timeout))
}

func newAIHTTPClient(cfg config.AIConfig, timeout time.Duration) *http.Client {
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: timeout,
		Policy: netguard.URLPolicy{
			Purpose:        "AI API base",
			HostPurpose:    "AI API base",
			AllowedSchemes: []string{"http", "https"},
			AllowPrivate:   cfg.AllowPrivateAPIBase,
		},
	})
}

func newOpenAISDKClient(apiBase, apiKey string, httpClient *http.Client) openaisdk.Client {
	options := []openaioption.RequestOption{
		openaioption.WithHTTPClient(httpClient),
		openaioption.WithMaxRetries(0),
		openaioption.WithAPIKey(apiKey),
	}
	if strings.TrimSpace(apiBase) != "" {
		options = append(options, openaioption.WithBaseURL(apiBase))
	}
	return openaisdk.NewClient(options...)
}

func openAIChatParams(model string, messages []Message) openaisdk.ChatCompletionNewParams {
	return openaisdk.ChatCompletionNewParams{
		Model:       openaishared.ChatModel(model),
		Messages:    openAIMessageParams(messages),
		Temperature: openaiparam.NewOpt(0.2),
	}
}

func openAIChatToolParams(model string, messages []Message, tools []map[string]any) (openaisdk.ChatCompletionNewParams, error) {
	params := openAIChatParams(model, messages)
	converted, err := openAIToolParams(tools)
	if err != nil {
		return params, err
	}
	params.Tools = converted
	params.ToolChoice = openaisdk.ChatCompletionToolChoiceOptionUnionParam{
		OfAuto: openaiparam.NewOpt("auto"),
	}
	return params, nil
}

func openAIMessageParams(messages []Message) []openaisdk.ChatCompletionMessageParamUnion {
	out := make([]openaisdk.ChatCompletionMessageParamUnion, 0, len(messages))
	for _, message := range messages {
		content := message.Content
		switch strings.ToLower(strings.TrimSpace(message.Role)) {
		case "system":
			out = append(out, openaisdk.SystemMessage(content))
		case "developer":
			out = append(out, openaisdk.DeveloperMessage(content))
		case "assistant":
			out = append(out, openaisdk.AssistantMessage(content))
		case "user", "":
			out = append(out, openaisdk.UserMessage(content))
		default:
			out = append(out, openaisdk.UserMessage(content))
		}
	}
	return out
}

func openAIToolParams(tools []map[string]any) ([]openaisdk.ChatCompletionToolParam, error) {
	if len(tools) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(tools)
	if err != nil {
		return nil, err
	}
	var converted []openaisdk.ChatCompletionToolParam
	if err := json.Unmarshal(raw, &converted); err != nil {
		return nil, err
	}
	return converted, nil
}

func openAIStreamOptions() openaisdk.ChatCompletionStreamOptionsParam {
	return openaisdk.ChatCompletionStreamOptionsParam{
		IncludeUsage: openaiparam.NewOpt(true),
	}
}

func openAIChunkRawJSON(chunk openaisdk.ChatCompletionChunk) string {
	if raw := strings.TrimSpace(chunk.RawJSON()); raw != "" {
		return raw
	}
	raw, err := json.Marshal(chunk)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func (c *Client) Complete(ctx context.Context, messages []Message) (string, error) {
	result, err := c.CompleteWithUsage(ctx, messages)
	if err != nil {
		return "", err
	}
	return result.Content, nil
}

func (c *Client) ListModels(ctx context.Context) ([]ModelInfo, error) {
	if c == nil {
		return nil, fmt.Errorf("ai client is nil")
	}
	if c.apiBase == "" {
		return nil, fmt.Errorf("ai api_base is required")
	}
	switch c.provider {
	case "openai":
		return c.listOpenAIModels(ctx)
	case "anthropic":
		return c.listAnthropicModels(ctx)
	default:
		return nil, fmt.Errorf("unsupported ai provider %q", c.provider)
	}
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

func (c *Client) CompleteWithUsageStream(ctx context.Context, messages []Message, emit StreamEmitter) (*CompletionResult, error) {
	if emit == nil {
		return c.CompleteWithUsage(ctx, messages)
	}
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
		result, started, err := c.completeOpenAIStream(ctx, messages, emit)
		if err == nil || started {
			return result, err
		}
		return c.completeOpenAI(ctx, messages)
	case "anthropic":
		result, started, err := c.completeAnthropicStream(ctx, messages, emit)
		if err == nil || started {
			return result, err
		}
		return c.completeAnthropic(ctx, messages)
	default:
		return nil, fmt.Errorf("unsupported ai provider %q", c.provider)
	}
}

func (c *Client) CompleteToolPlanStream(ctx context.Context, messages []Message, tools []map[string]any, emit StreamEmitter) (*AssistantPlan, error) {
	if emit == nil {
		return c.CompleteToolPlan(ctx, messages, tools)
	}
	if c == nil {
		return nil, fmt.Errorf("ai client is nil")
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("tool definitions are required")
	}
	switch c.provider {
	case "openai":
		plan, started, err := c.completeOpenAIToolPlanStream(ctx, messages, tools, emit)
		if err == nil || started {
			return plan, err
		}
		return c.completeOpenAIToolPlan(ctx, messages, tools)
	case "anthropic":
		plan, started, err := c.completeAnthropicToolPlanStream(ctx, messages, tools, emit)
		if err == nil || started {
			return plan, err
		}
		return c.completeAnthropicToolPlan(ctx, messages, tools)
	default:
		return nil, fmt.Errorf("unsupported ai provider %q", c.provider)
	}
}

func (c *Client) completeOpenAI(ctx context.Context, messages []Message) (*CompletionResult, error) {
	completion, err := c.openai.Chat.Completions.New(ctx, openAIChatParams(c.model, messages))
	if err != nil {
		return nil, err
	}
	var parsed chatResponse
	if err := json.Unmarshal([]byte(completion.RawJSON()), &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("ai api returned no choices")
	}
	return &CompletionResult{
		Content:          strings.TrimSpace(parsed.Choices[0].Message.Content),
		ReasoningSummary: sanitizeAssistantReasoningSummary(firstNonEmpty(parsed.Choices[0].Message.ReasoningContent, parsed.Choices[0].Message.Reasoning)),
		Provider:         c.provider,
		Model:            c.model,
		Usage: CompletionUsage{
			InputTokens:  parsed.Usage.PromptTokens,
			OutputTokens: parsed.Usage.CompletionTokens,
			TotalTokens:  parsed.Usage.TotalTokens,
		},
	}, nil
}

func (c *Client) completeOpenAIToolPlan(ctx context.Context, messages []Message, tools []map[string]any) (*AssistantPlan, error) {
	params, err := openAIChatToolParams(c.model, messages, tools)
	if err != nil {
		return nil, err
	}
	completion, err := c.openai.Chat.Completions.New(ctx, params)
	if err != nil {
		return nil, err
	}
	var parsed chatResponse
	if err := json.Unmarshal([]byte(completion.RawJSON()), &parsed); err != nil {
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
	plan.ReasoningSummary = strings.TrimSpace(firstNonEmpty(message.ReasoningContent, message.Reasoning))
	plan.InputTokens = parsed.Usage.PromptTokens
	plan.OutputTokens = parsed.Usage.CompletionTokens
	plan.TotalTokens = parsed.Usage.TotalTokens
	return plan, nil
}

func (c *Client) listOpenAIModels(ctx context.Context) ([]ModelInfo, error) {
	endpoint, err := c.endpoint("/models")
	if err != nil {
		return nil, err
	}
	req, err := netguard.NewRequest(ctx, http.MethodGet, endpoint, nil, c.urlPolicy())
	if err != nil {
		return nil, err
	}
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
	var parsed struct {
		Data []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
			Created int64  `json:"created"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	models := make([]ModelInfo, 0, len(parsed.Data))
	seen := map[string]bool{}
	for _, item := range parsed.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		models = append(models, ModelInfo{ID: id, OwnedBy: item.OwnedBy, Created: item.Created})
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("ai api returned no models")
	}
	return models, nil
}

func (c *Client) completeOpenAIStream(ctx context.Context, messages []Message, emit StreamEmitter) (*CompletionResult, bool, error) {
	params := openAIChatParams(c.model, messages)
	params.StreamOptions = openAIStreamOptions()
	stream := c.openai.Chat.Completions.NewStreaming(ctx, params)
	defer stream.Close()
	assembler := newOpenAIStreamAssembler(c.provider, c.model, emit)
	for stream.Next() {
		if err := assembler.accept(openAIChunkRawJSON(stream.Current())); err != nil {
			return nil, assembler.started, err
		}
	}
	if err := stream.Err(); err != nil {
		return nil, assembler.started, err
	}
	if !assembler.started {
		return nil, false, fmt.Errorf("ai stream returned no events")
	}
	return assembler.completion(), assembler.started, nil
}

func (c *Client) completeOpenAIToolPlanStream(ctx context.Context, messages []Message, tools []map[string]any, emit StreamEmitter) (*AssistantPlan, bool, error) {
	params, err := openAIChatToolParams(c.model, messages, tools)
	if err != nil {
		return nil, false, err
	}
	params.StreamOptions = openAIStreamOptions()
	stream := c.openai.Chat.Completions.NewStreaming(ctx, params)
	defer stream.Close()
	assembler := newOpenAIStreamAssembler(c.provider, c.model, emit)
	for stream.Next() {
		if err := assembler.accept(openAIChunkRawJSON(stream.Current())); err != nil {
			return nil, assembler.started, err
		}
	}
	if err := stream.Err(); err != nil {
		return nil, assembler.started, err
	}
	if !assembler.started {
		return nil, false, fmt.Errorf("ai stream returned no events")
	}
	return assembler.plan(), assembler.started, nil
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
	endpoint, err := c.endpoint("/messages")
	if err != nil {
		return nil, err
	}
	req, err := netguard.NewRequest(ctx, http.MethodPost, endpoint, bytes.NewReader(body), c.urlPolicy())
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
	var reasoning []string
	for _, block := range parsed.Content {
		if strings.TrimSpace(block.Thinking) != "" {
			reasoning = append(reasoning, strings.TrimSpace(block.Thinking))
			continue
		}
		if block.Type == "thinking" && strings.TrimSpace(block.Text) != "" {
			reasoning = append(reasoning, strings.TrimSpace(block.Text))
			continue
		}
		if strings.TrimSpace(block.Text) != "" {
			parts = append(parts, strings.TrimSpace(block.Text))
		}
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("ai api returned no content")
	}
	return &CompletionResult{
		Content:          strings.Join(parts, "\n"),
		ReasoningSummary: sanitizeAssistantReasoningSummary(strings.Join(reasoning, "\n")),
		Provider:         c.provider,
		Model:            c.model,
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
	endpoint, err := c.endpoint("/messages")
	if err != nil {
		return nil, err
	}
	req, err := netguard.NewRequest(ctx, http.MethodPost, endpoint, bytes.NewReader(body), c.urlPolicy())
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
	var reasoning []string
	var requests []AssistantToolRequest
	for _, block := range parsed.Content {
		switch block.Type {
		case "tool_use":
			requests = append(requests, AssistantToolRequest{Name: block.Name, Args: block.Input})
		case "thinking":
			if strings.TrimSpace(block.Thinking) != "" {
				reasoning = append(reasoning, strings.TrimSpace(block.Thinking))
			} else if strings.TrimSpace(block.Text) != "" {
				reasoning = append(reasoning, strings.TrimSpace(block.Text))
			}
		default:
			if strings.TrimSpace(block.Thinking) != "" {
				reasoning = append(reasoning, strings.TrimSpace(block.Thinking))
				continue
			}
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
	plan.ReasoningSummary = strings.Join(reasoning, "\n")
	plan.InputTokens = parsed.Usage.InputTokens
	plan.OutputTokens = parsed.Usage.OutputTokens
	plan.TotalTokens = parsed.Usage.InputTokens + parsed.Usage.OutputTokens
	return plan, nil
}

func (c *Client) listAnthropicModels(ctx context.Context) ([]ModelInfo, error) {
	endpoint, err := c.endpoint("/models")
	if err != nil {
		return nil, err
	}
	req, err := netguard.NewRequest(ctx, http.MethodGet, endpoint, nil, c.urlPolicy())
	if err != nil {
		return nil, err
	}
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
	var parsed struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			CreatedAt   string `json:"created_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	models := make([]ModelInfo, 0, len(parsed.Data))
	seen := map[string]bool{}
	for _, item := range parsed.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		models = append(models, ModelInfo{ID: id, OwnedBy: strings.TrimSpace(item.DisplayName)})
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("ai api returned no models")
	}
	return models, nil
}

func (c *Client) completeAnthropicStream(ctx context.Context, messages []Message, emit StreamEmitter) (*CompletionResult, bool, error) {
	payload := c.anthropicPayload(messages, nil)
	payload.Stream = true
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.doAnthropicRequest(ctx, body)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("ai api returned %s", resp.Status)
	}
	assembler := newAnthropicStreamAssembler(c.provider, c.model, emit)
	if err := readSSE(resp.Body, func(_ string, data string) error {
		return assembler.accept(data)
	}); err != nil {
		return nil, assembler.started, err
	}
	if !assembler.started {
		return nil, false, fmt.Errorf("ai stream returned no events")
	}
	return assembler.completion(), assembler.started, nil
}

func (c *Client) completeAnthropicToolPlanStream(ctx context.Context, messages []Message, tools []map[string]any, emit StreamEmitter) (*AssistantPlan, bool, error) {
	payload := c.anthropicPayload(messages, tools)
	payload.Stream = true
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.doAnthropicRequest(ctx, body)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("ai api returned %s", resp.Status)
	}
	assembler := newAnthropicStreamAssembler(c.provider, c.model, emit)
	if err := readSSE(resp.Body, func(_ string, data string) error {
		return assembler.accept(data)
	}); err != nil {
		return nil, assembler.started, err
	}
	if !assembler.started {
		return nil, false, fmt.Errorf("ai stream returned no events")
	}
	return assembler.plan(), assembler.started, nil
}

func (c *Client) anthropicPayload(messages []Message, tools []map[string]any) anthropicRequest {
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
	if len(tools) > 0 {
		payload.Tools = anthropicTools(tools)
	}
	return payload
}

func (c *Client) doAnthropicRequest(ctx context.Context, body []byte) (*http.Response, error) {
	endpoint, err := c.endpoint("/messages")
	if err != nil {
		return nil, err
	}
	req, err := netguard.NewRequest(ctx, http.MethodPost, endpoint, bytes.NewReader(body), c.urlPolicy())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	if c.apiKey != "" {
		req.Header.Set("x-api-key", c.apiKey)
	}
	return c.http.Do(req)
}

func (c *Client) endpoint(path string) (string, error) {
	base, err := url.Parse(strings.TrimRight(c.apiBase, "/") + "/")
	if err != nil {
		return "", err
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", fmt.Errorf("ai api base must use http or https")
	}
	if base.Host == "" {
		return "", fmt.Errorf("ai api base host is required")
	}
	ref := &url.URL{Path: strings.TrimPrefix(path, "/")}
	return base.ResolveReference(ref).String(), nil
}

func (c *Client) urlPolicy() netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "AI API base",
		HostPurpose:    "AI API base",
		AllowedSchemes: []string{"http", "https"},
		AllowPrivate:   c.allowPrivate,
	}
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
	Model         string           `json:"model"`
	Messages      []Message        `json:"messages"`
	Temperature   float64          `json:"temperature"`
	Tools         []map[string]any `json:"tools,omitempty"`
	ToolChoice    any              `json:"tool_choice,omitempty"`
	Stream        bool             `json:"stream,omitempty"`
	StreamOptions map[string]any   `json:"stream_options,omitempty"`
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
	Role             string         `json:"role"`
	Content          string         `json:"content"`
	Reasoning        string         `json:"reasoning"`
	ReasoningContent string         `json:"reasoning_content"`
	ToolCalls        []chatToolCall `json:"tool_calls"`
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
	Stream      bool               `json:"stream,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type     string         `json:"type"`
		Text     string         `json:"text"`
		Thinking string         `json:"thinking"`
		ID       string         `json:"id"`
		Name     string         `json:"name"`
		Input    map[string]any `json:"input"`
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

type chatStreamChunk struct {
	Choices []struct {
		Delta struct {
			Role             string               `json:"role"`
			Content          string               `json:"content"`
			Reasoning        string               `json:"reasoning"`
			ReasoningContent string               `json:"reasoning_content"`
			ToolCalls        []chatStreamToolCall `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

type chatStreamToolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type anthropicStreamChunk struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type  string         `json:"type"`
		ID    string         `json:"id"`
		Name  string         `json:"name"`
		Text  string         `json:"text"`
		Input map[string]any `json:"input"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Thinking    string `json:"thinking"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
	Message struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type openAIStreamAssembler struct {
	provider     string
	model        string
	emit         StreamEmitter
	started      bool
	content      strings.Builder
	reasoning    strings.Builder
	usage        CompletionUsage
	toolCalls    map[int]*chatToolCall
	toolArgParts map[int]*strings.Builder
}

func newOpenAIStreamAssembler(provider, model string, emit StreamEmitter) *openAIStreamAssembler {
	return &openAIStreamAssembler{
		provider:     provider,
		model:        model,
		emit:         emit,
		toolCalls:    map[int]*chatToolCall{},
		toolArgParts: map[int]*strings.Builder{},
	}
}

func (a *openAIStreamAssembler) accept(data string) error {
	var chunk chatStreamChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return err
	}
	if chunk.Usage.PromptTokens > 0 || chunk.Usage.CompletionTokens > 0 || chunk.Usage.TotalTokens > 0 {
		a.usage = CompletionUsage{
			InputTokens:  chunk.Usage.PromptTokens,
			OutputTokens: chunk.Usage.CompletionTokens,
			TotalTokens:  chunk.Usage.TotalTokens,
		}
	}
	for _, choice := range chunk.Choices {
		a.markStarted()
		if delta := firstPresent(choice.Delta.ReasoningContent, choice.Delta.Reasoning); delta != "" {
			a.reasoning.WriteString(delta)
			a.emitDelta("reasoning_delta", delta, "")
		}
		if choice.Delta.Content != "" {
			a.content.WriteString(choice.Delta.Content)
			a.emitDelta("content_delta", choice.Delta.Content, "")
		}
		for _, delta := range choice.Delta.ToolCalls {
			call := a.toolCalls[delta.Index]
			if call == nil {
				call = &chatToolCall{ID: delta.ID, Type: firstNonEmpty(delta.Type, "function")}
				a.toolCalls[delta.Index] = call
			}
			if delta.ID != "" {
				call.ID = delta.ID
			}
			if delta.Type != "" {
				call.Type = delta.Type
			}
			if delta.Function.Name != "" {
				call.Function.Name += delta.Function.Name
			}
			if delta.Function.Arguments != "" {
				builder := a.toolArgParts[delta.Index]
				if builder == nil {
					builder = &strings.Builder{}
					a.toolArgParts[delta.Index] = builder
				}
				builder.WriteString(delta.Function.Arguments)
				call.Function.Arguments = builder.String()
			}
			a.emitToolDelta(call.Function.Name, delta.Function.Arguments)
		}
	}
	return nil
}

func firstPresent(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (a *openAIStreamAssembler) completion() *CompletionResult {
	return &CompletionResult{
		Content:          strings.TrimSpace(a.content.String()),
		ReasoningSummary: sanitizeAssistantReasoningSummary(a.reasoning.String()),
		Provider:         a.provider,
		Model:            a.model,
		Usage:            a.usage,
	}
}

func (a *openAIStreamAssembler) plan() *AssistantPlan {
	result := a.completion()
	plan := parseAssistantPlan(result.Content)
	requests := a.toolRequests()
	if len(requests) > 0 {
		plan.ToolRequests = requests
		plan.Answer = strings.TrimSpace(result.Content)
		plan.Mode = "native_openai_tool_calls_stream"
	} else if plan.Mode == "" {
		plan.Mode = "native_openai_no_tool_call_stream"
	}
	plan.Provider = result.Provider
	plan.Model = result.Model
	plan.ReasoningSummary = result.ReasoningSummary
	plan.InputTokens = result.Usage.InputTokens
	plan.OutputTokens = result.Usage.OutputTokens
	plan.TotalTokens = result.Usage.TotalTokens
	return plan
}

func (a *openAIStreamAssembler) toolRequests() []AssistantToolRequest {
	requests := make([]AssistantToolRequest, 0, len(a.toolCalls))
	for i := 0; i < len(a.toolCalls); i++ {
		call := a.toolCalls[i]
		if call == nil || strings.TrimSpace(call.Function.Name) == "" {
			continue
		}
		args := map[string]any{}
		if strings.TrimSpace(call.Function.Arguments) != "" {
			decoder := json.NewDecoder(strings.NewReader(call.Function.Arguments))
			decoder.UseNumber()
			if err := decoder.Decode(&args); err != nil {
				args = map[string]any{"raw_arguments": call.Function.Arguments}
			}
		}
		requests = append(requests, AssistantToolRequest{Name: call.Function.Name, Args: args})
	}
	return requests
}

func (a *openAIStreamAssembler) markStarted() {
	if a.started {
		return
	}
	a.started = true
	a.emitEvent(AssistantTraceEvent{Type: "provider_response_start", Provider: a.provider, Model: a.model})
}

func (a *openAIStreamAssembler) emitDelta(kind, delta, tool string) {
	if delta == "" {
		return
	}
	a.emitEvent(AssistantTraceEvent{Type: kind, Message: delta, ToolName: tool, Provider: a.provider, Model: a.model})
}

func (a *openAIStreamAssembler) emitToolDelta(name, argsDelta string) {
	if strings.TrimSpace(name) == "" && strings.TrimSpace(argsDelta) == "" {
		return
	}
	a.emitEvent(AssistantTraceEvent{Type: "tool_call_delta", Message: argsDelta, ToolName: name, Provider: a.provider, Model: a.model})
}

func (a *openAIStreamAssembler) emitEvent(event AssistantTraceEvent) {
	if a.emit != nil {
		a.emit(event)
	}
}

type anthropicStreamBlock struct {
	kind       string
	name       string
	text       strings.Builder
	thinking   strings.Builder
	inputJSON  strings.Builder
	input      map[string]any
	outputSeen bool
}

type anthropicStreamAssembler struct {
	provider  string
	model     string
	emit      StreamEmitter
	started   bool
	blocks    map[int]*anthropicStreamBlock
	content   strings.Builder
	reasoning strings.Builder
	usage     CompletionUsage
}

func newAnthropicStreamAssembler(provider, model string, emit StreamEmitter) *anthropicStreamAssembler {
	return &anthropicStreamAssembler{
		provider: provider,
		model:    model,
		emit:     emit,
		blocks:   map[int]*anthropicStreamBlock{},
	}
}

func (a *anthropicStreamAssembler) accept(data string) error {
	if strings.TrimSpace(data) == "" {
		return nil
	}
	var chunk anthropicStreamChunk
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return err
	}
	switch chunk.Type {
	case "message_start":
		a.markStarted()
		if chunk.Message.Usage.InputTokens > 0 {
			a.usage.InputTokens = chunk.Message.Usage.InputTokens
		}
	case "content_block_start":
		a.markStarted()
		block := a.block(chunk.Index)
		block.kind = chunk.ContentBlock.Type
		block.name = chunk.ContentBlock.Name
		block.input = chunk.ContentBlock.Input
		if chunk.ContentBlock.Text != "" {
			block.text.WriteString(chunk.ContentBlock.Text)
		}
	case "content_block_delta":
		a.markStarted()
		block := a.block(chunk.Index)
		switch chunk.Delta.Type {
		case "thinking_delta":
			block.thinking.WriteString(chunk.Delta.Thinking)
			a.reasoning.WriteString(chunk.Delta.Thinking)
			a.emitDelta("reasoning_delta", chunk.Delta.Thinking, block.name)
		case "text_delta":
			block.text.WriteString(chunk.Delta.Text)
			a.content.WriteString(chunk.Delta.Text)
			a.emitDelta("content_delta", chunk.Delta.Text, block.name)
		case "input_json_delta":
			block.inputJSON.WriteString(chunk.Delta.PartialJSON)
			a.emitToolDelta(block.name, chunk.Delta.PartialJSON)
		}
	case "message_delta":
		if chunk.Usage.OutputTokens > 0 {
			a.usage.OutputTokens = chunk.Usage.OutputTokens
		}
	case "content_block_stop":
		block := a.block(chunk.Index)
		if block.input == nil && strings.TrimSpace(block.inputJSON.String()) != "" {
			var input map[string]any
			decoder := json.NewDecoder(strings.NewReader(block.inputJSON.String()))
			decoder.UseNumber()
			if err := decoder.Decode(&input); err == nil {
				block.input = input
			}
		}
	}
	if a.usage.InputTokens > 0 || a.usage.OutputTokens > 0 {
		a.usage.TotalTokens = a.usage.InputTokens + a.usage.OutputTokens
	}
	return nil
}

func (a *anthropicStreamAssembler) completion() *CompletionResult {
	if strings.TrimSpace(a.content.String()) == "" {
		for i := 0; i < len(a.blocks); i++ {
			if block := a.blocks[i]; block != nil && block.kind == "text" {
				a.content.WriteString(block.text.String())
			}
		}
	}
	return &CompletionResult{
		Content:          strings.TrimSpace(a.content.String()),
		ReasoningSummary: sanitizeAssistantReasoningSummary(a.reasoning.String()),
		Provider:         a.provider,
		Model:            a.model,
		Usage:            a.usage,
	}
}

func (a *anthropicStreamAssembler) plan() *AssistantPlan {
	result := a.completion()
	plan := parseAssistantPlan(result.Content)
	requests := a.toolRequests()
	if len(requests) > 0 {
		plan.ToolRequests = requests
		plan.Answer = strings.TrimSpace(result.Content)
		plan.Mode = "native_anthropic_tool_use_stream"
	} else if plan.Mode == "" {
		plan.Mode = "native_anthropic_no_tool_use_stream"
	}
	plan.Provider = result.Provider
	plan.Model = result.Model
	plan.ReasoningSummary = result.ReasoningSummary
	plan.InputTokens = result.Usage.InputTokens
	plan.OutputTokens = result.Usage.OutputTokens
	plan.TotalTokens = result.Usage.TotalTokens
	return plan
}

func (a *anthropicStreamAssembler) toolRequests() []AssistantToolRequest {
	requests := make([]AssistantToolRequest, 0)
	for i := 0; i < len(a.blocks); i++ {
		block := a.blocks[i]
		if block == nil || block.kind != "tool_use" || strings.TrimSpace(block.name) == "" {
			continue
		}
		args := block.input
		if args == nil {
			args = map[string]any{}
			if raw := strings.TrimSpace(block.inputJSON.String()); raw != "" {
				args["raw_arguments"] = raw
			}
		}
		requests = append(requests, AssistantToolRequest{Name: block.name, Args: args})
	}
	return requests
}

func (a *anthropicStreamAssembler) block(index int) *anthropicStreamBlock {
	block := a.blocks[index]
	if block == nil {
		block = &anthropicStreamBlock{}
		a.blocks[index] = block
	}
	return block
}

func (a *anthropicStreamAssembler) markStarted() {
	if a.started {
		return
	}
	a.started = true
	a.emitEvent(AssistantTraceEvent{Type: "provider_response_start", Provider: a.provider, Model: a.model})
}

func (a *anthropicStreamAssembler) emitDelta(kind, delta, tool string) {
	if delta == "" {
		return
	}
	a.emitEvent(AssistantTraceEvent{Type: kind, Message: delta, ToolName: tool, Provider: a.provider, Model: a.model})
}

func (a *anthropicStreamAssembler) emitToolDelta(name, argsDelta string) {
	if strings.TrimSpace(name) == "" && strings.TrimSpace(argsDelta) == "" {
		return
	}
	a.emitEvent(AssistantTraceEvent{Type: "tool_call_delta", Message: argsDelta, ToolName: name, Provider: a.provider, Model: a.model})
}

func (a *anthropicStreamAssembler) emitEvent(event AssistantTraceEvent) {
	if a.emit != nil {
		a.emit(event)
	}
}

func readSSE(body io.Reader, handle func(event string, data string) error) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var eventName string
	var dataLines []string
	flush := func() error {
		if len(dataLines) == 0 {
			eventName = ""
			return nil
		}
		data := strings.Join(dataLines, "\n")
		dataLines = nil
		event := eventName
		eventName = ""
		return handle(event, data)
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		value = strings.TrimPrefix(value, " ")
		switch name {
		case "event":
			eventName = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
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
