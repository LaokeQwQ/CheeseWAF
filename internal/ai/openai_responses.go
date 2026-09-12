package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	openaisdk "github.com/openai/openai-go"
	openaioption "github.com/openai/openai-go/packages/param"
	openairesponses "github.com/openai/openai-go/responses"
	openaishared "github.com/openai/openai-go/shared"
)

type openAIProtocol uint8

const (
	openAIProtocolChat openAIProtocol = iota
	openAIProtocolResponses
)

func shouldUseOpenAIResponses(provider, apiBase string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai-responses", "openai_responses", "openai-response", "openai_response":
		return true
	case "openai-chat", "openai_chat", "openai-chat-completions", "openai_chat_completions":
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(apiBase))
	return err == nil && strings.EqualFold(parsed.Hostname(), "api.openai.com")
}

func (c *Client) completeOpenAI(ctx context.Context, messages []Message) (*CompletionResult, error) {
	if c.openAIResponses {
		result, err := c.completeOpenAIResponse(ctx, messages)
		if err == nil || !openAIResponsesUnavailable(err) {
			return result, err
		}
	}
	return c.completeOpenAIChat(ctx, messages)
}

func (c *Client) completeOpenAIToolPlan(ctx context.Context, messages []Message, tools []map[string]any) (*AssistantPlan, error) {
	if c.openAIResponses {
		plan, err := c.completeOpenAIResponseToolPlan(ctx, messages, tools)
		if err == nil || !openAIResponsesUnavailable(err) {
			return plan, err
		}
	}
	return c.completeOpenAIChatToolPlan(ctx, messages, tools)
}

func (c *Client) completeOpenAIStream(ctx context.Context, messages []Message, emit StreamEmitter) (*CompletionResult, bool, openAIProtocol, error) {
	if c.openAIResponses {
		result, started, err := c.completeOpenAIResponseStream(ctx, messages, emit)
		if err == nil || started || !openAIResponsesUnavailable(err) {
			return result, started, openAIProtocolResponses, err
		}
	}
	result, started, err := c.completeOpenAIChatStream(ctx, messages, emit)
	return result, started, openAIProtocolChat, err
}

func (c *Client) completeOpenAIToolPlanStream(ctx context.Context, messages []Message, tools []map[string]any, emit StreamEmitter) (*AssistantPlan, bool, openAIProtocol, error) {
	if c.openAIResponses {
		plan, started, err := c.completeOpenAIResponseToolPlanStream(ctx, messages, tools, emit)
		if err == nil || started || !openAIResponsesUnavailable(err) {
			return plan, started, openAIProtocolResponses, err
		}
	}
	plan, started, err := c.completeOpenAIChatToolPlanStream(ctx, messages, tools, emit)
	return plan, started, openAIProtocolChat, err
}

func openAIResponsesUnavailable(err error) bool {
	var apiErr *openaisdk.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	if openAIErrorProhibitsFallback(apiErr) {
		return false
	}
	if openAIStreamOnlyUnavailable(apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	case http.StatusNotFound:
		return openAIEndpointNotFound(apiErr)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		message := strings.ToLower(strings.Join([]string{apiErr.Code, apiErr.Type, apiErr.Message}, " "))
		return strings.Contains(message, "chat/completions") ||
			(strings.Contains(message, "responses api") && strings.Contains(message, "not support")) ||
			strings.Contains(message, "unsupported_endpoint")
	default:
		return false
	}
}

func openAIEndpointNotFound(apiErr *openaisdk.Error) bool {
	if apiErr == nil {
		return false
	}
	signal := openAIErrorSignal(apiErr)
	for _, code := range []string{"endpoint_not_found", "route_not_found", "unknown_endpoint", "unsupported_endpoint"} {
		if strings.Contains(signal, code) {
			return true
		}
	}
	return strings.Contains(signal, "unknown endpoint") ||
		(strings.Contains(signal, "responses") &&
			(strings.Contains(signal, "endpoint") || strings.Contains(signal, "route") || strings.Contains(signal, "invalid url")))
}

func openAIStreamFallbackSafe(err error) bool {
	var apiErr *openaisdk.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	if openAIErrorProhibitsFallback(apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusMethodNotAllowed, http.StatusNotAcceptable, http.StatusUnsupportedMediaType, http.StatusNotImplemented:
		return true
	case http.StatusNotFound:
		return openAIEndpointNotFound(apiErr)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		signal := strings.ToLower(strings.Join([]string{apiErr.Code, apiErr.Type, apiErr.Message}, " "))
		return strings.Contains(signal, "stream unsupported") ||
			strings.Contains(signal, "streaming unsupported") ||
			(strings.Contains(signal, "stream") && strings.Contains(signal, "not support"))
	default:
		return false
	}
}

func openAIErrorSignal(apiErr *openaisdk.Error) string {
	if apiErr == nil {
		return ""
	}
	return strings.ToLower(strings.Join([]string{apiErr.Code, apiErr.Type, apiErr.Message}, " "))
}

func openAIErrorProhibitsFallback(apiErr *openaisdk.Error) bool {
	signal := strings.NewReplacer("_", " ", "-", " ").Replace(openAIErrorSignal(apiErr))
	for _, sensitive := range []string{
		"auth", "unauthorized", "credential", "api key", "access denied",
		"permission", "forbidden", "policy", "model", "resource",
	} {
		if strings.Contains(signal, sensitive) {
			return true
		}
	}
	return false
}

func openAIStreamOnlyUnavailable(apiErr *openaisdk.Error) bool {
	signal := openAIErrorSignal(apiErr)
	return strings.Contains(signal, "stream") &&
		(strings.Contains(signal, "not support") || strings.Contains(signal, "unsupported"))
}

func (c *Client) openAIResponseParams(messages []Message) openairesponses.ResponseNewParams {
	input := make(openairesponses.ResponseInputParam, 0, len(messages))
	for _, message := range messages {
		input = append(input, openairesponses.ResponseInputItemParamOfMessage(message.Content, openAIResponseRole(message.Role)))
	}
	params := openairesponses.ResponseNewParams{
		Input: openairesponses.ResponseNewParamsInputUnion{
			OfInputItemList: input,
		},
		MaxOutputTokens: openaioption.NewOpt(int64(c.maxTokens)),
		Model:           openaishared.ResponsesModel(c.model),
		Store:           openaioption.NewOpt(false),
	}
	if effort := normalizeReasoningEffort(c.reasoningEffort); effort != "" {
		params.Reasoning = openaishared.ReasoningParam{
			Effort:  openaishared.ReasoningEffort(effort),
			Summary: openaishared.ReasoningSummaryAuto,
		}
	}
	return params
}

func openAIResponseRole(role string) openairesponses.EasyInputMessageRole {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "system":
		return openairesponses.EasyInputMessageRoleSystem
	case "developer":
		return openairesponses.EasyInputMessageRoleDeveloper
	case "assistant":
		return openairesponses.EasyInputMessageRoleAssistant
	default:
		return openairesponses.EasyInputMessageRoleUser
	}
}

func openAIResponseToolParams(tools []map[string]any) ([]openairesponses.ToolUnionParam, error) {
	converted := make([]openairesponses.ToolUnionParam, 0, len(tools))
	for index, tool := range tools {
		kind, _ := tool["type"].(string)
		if kind != "" && !strings.EqualFold(strings.TrimSpace(kind), "function") {
			return nil, fmt.Errorf("openai responses tool %d has unsupported type %q", index, kind)
		}
		definition, ok := tool["function"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("openai responses tool %d is missing function definition", index)
		}
		name, _ := definition["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("openai responses tool %d is missing function name", index)
		}
		parameters, _ := definition["parameters"].(map[string]any)
		if parameters == nil {
			parameters = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		strict, _ := definition["strict"].(bool)
		function := &openairesponses.FunctionToolParam{
			Name:       name,
			Parameters: parameters,
			Strict:     openaioption.NewOpt(strict),
		}
		if description, _ := definition["description"].(string); strings.TrimSpace(description) != "" {
			function.Description = openaioption.NewOpt(description)
		}
		converted = append(converted, openairesponses.ToolUnionParam{OfFunction: function})
	}
	return converted, nil
}

func (c *Client) openAIResponseToolParams(messages []Message, tools []map[string]any) (openairesponses.ResponseNewParams, error) {
	params := c.openAIResponseParams(messages)
	converted, err := openAIResponseToolParams(tools)
	if err != nil {
		return params, err
	}
	params.Tools = converted
	params.ToolChoice = openairesponses.ResponseNewParamsToolChoiceUnion{
		OfToolChoiceMode: openaioption.NewOpt(openairesponses.ToolChoiceOptionsAuto),
	}
	return params, nil
}

func (c *Client) completeOpenAIResponse(ctx context.Context, messages []Message) (*CompletionResult, error) {
	response, err := c.openai.Responses.New(ctx, c.openAIResponseParams(messages))
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("openai responses api returned no response")
	}
	result := openAIResponseCompletion(response, c.provider, c.model)
	if err := validateOpenAIResponse(response); err != nil {
		return result, err
	}
	if strings.TrimSpace(result.Content) == "" {
		return result, fmt.Errorf("openai responses api returned no visible output")
	}
	return result, nil
}

func (c *Client) completeOpenAIResponseToolPlan(ctx context.Context, messages []Message, tools []map[string]any) (*AssistantPlan, error) {
	params, err := c.openAIResponseToolParams(messages, tools)
	if err != nil {
		return nil, err
	}
	response, err := c.openai.Responses.New(ctx, params)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("openai responses api returned no response")
	}
	plan, err := openAIResponsePlan(response, c.provider, c.model)
	if err != nil {
		return plan, err
	}
	if err := validateOpenAIResponse(response); err != nil {
		return plan, err
	}
	if strings.TrimSpace(plan.Answer) == "" && len(plan.ToolRequests) == 0 {
		return plan, fmt.Errorf("openai responses api returned no visible output or tool call")
	}
	return plan, nil
}

func validateOpenAIResponse(response *openairesponses.Response) error {
	if response == nil {
		return fmt.Errorf("openai responses api returned no response")
	}
	switch strings.ToLower(strings.TrimSpace(string(response.Status))) {
	case "failed", "cancelled":
		return fmt.Errorf("openai responses api returned status %s", response.Status)
	}
	if len(response.Output) == 0 {
		return fmt.Errorf("openai responses api returned no output")
	}
	return nil
}

func openAIResponseCompletion(response *openairesponses.Response, provider, model string) *CompletionResult {
	return &CompletionResult{
		Content:          strings.TrimSpace(openAIResponseVisibleText(response.Output)),
		ReasoningSummary: sanitizeAssistantReasoningSummary(openAIResponseReasoningSummary(response.Output)),
		Provider:         provider,
		Model:            model,
		Usage:            openAIResponseUsage(response.Usage),
	}
}

func openAIResponseVisibleText(output []openairesponses.ResponseOutputItemUnion) string {
	var text strings.Builder
	for _, item := range output {
		if item.Type != "message" {
			continue
		}
		for _, content := range item.Content {
			switch content.Type {
			case "output_text":
				text.WriteString(content.Text)
			case "refusal":
				text.WriteString(content.Refusal)
			}
		}
	}
	return text.String()
}

func openAIResponsePlan(response *openairesponses.Response, provider, model string) (*AssistantPlan, error) {
	result := openAIResponseCompletion(response, provider, model)
	plan := parseAssistantPlan(result.Content)
	plan.Provider = result.Provider
	plan.Model = result.Model
	plan.ReasoningSummary = result.ReasoningSummary
	plan.InputTokens = result.Usage.InputTokens
	plan.OutputTokens = result.Usage.OutputTokens
	plan.TotalTokens = result.Usage.TotalTokens
	requests := make([]AssistantToolRequest, 0)
	for _, item := range response.Output {
		if item.Type != "function_call" || strings.TrimSpace(item.Name) == "" {
			continue
		}
		args, err := decodeOpenAIToolArguments(item.Name, item.Arguments)
		if err != nil {
			return plan, err
		}
		requests = append(requests, AssistantToolRequest{Name: item.Name, Args: args})
	}
	if len(requests) > 0 {
		plan.ToolRequests = requests
		plan.Answer = result.Content
		plan.Mode = "native_openai_tool_calls"
	} else if plan.Mode == "" {
		plan.Mode = "native_openai_no_tool_call"
	}
	return plan, nil
}

func openAIResponseReasoningSummary(output []openairesponses.ResponseOutputItemUnion) string {
	parts := make([]string, 0)
	for _, item := range output {
		if item.Type != "reasoning" {
			continue
		}
		for _, summary := range item.Summary {
			if text := strings.TrimSpace(summary.Text); text != "" {
				parts = append(parts, text)
			}
		}
	}
	return strings.Join(parts, "\n")
}

func openAIResponseUsage(usage openairesponses.ResponseUsage) CompletionUsage {
	return CompletionUsage{
		InputTokens:  boundedResponseTokenCount(usage.InputTokens),
		OutputTokens: boundedResponseTokenCount(usage.OutputTokens),
		TotalTokens:  boundedResponseTokenCount(usage.TotalTokens),
	}
}

func boundedResponseTokenCount(value int64) int {
	if value <= 0 {
		return 0
	}
	maxInt := int64(^uint(0) >> 1)
	if value > maxInt {
		return int(maxInt)
	}
	return int(value)
}

func decodeOpenAIToolArguments(name, arguments string) (map[string]any, error) {
	args := map[string]any{}
	if strings.TrimSpace(arguments) == "" {
		return args, nil
	}
	decoder := json.NewDecoder(strings.NewReader(arguments))
	decoder.UseNumber()
	if err := decoder.Decode(&args); err != nil {
		return nil, fmt.Errorf("decode tool arguments for %s: %w", name, err)
	}
	return args, nil
}

func (c *Client) completeOpenAIResponseStream(ctx context.Context, messages []Message, emit StreamEmitter) (*CompletionResult, bool, error) {
	stream := c.openai.Responses.NewStreaming(ctx, c.openAIResponseParams(messages))
	defer stream.Close()
	assembler := newOpenAIResponseStreamAssembler(c.provider, c.model, emit)
	for stream.Next() {
		if err := assembler.accept(stream.Current().RawJSON()); err != nil {
			return assembler.completion(), assembler.started, err
		}
	}
	if err := stream.Err(); err != nil {
		return nil, assembler.started, err
	}
	if !assembler.started {
		return nil, false, fmt.Errorf("ai stream returned no events")
	}
	if !assembler.terminal {
		return assembler.completion(), true, fmt.Errorf("ai stream ended before a terminal event")
	}
	result := assembler.completion()
	if strings.TrimSpace(result.Content) == "" {
		return result, true, fmt.Errorf("openai responses api returned no visible output")
	}
	return result, true, nil
}

func (c *Client) completeOpenAIResponseToolPlanStream(ctx context.Context, messages []Message, tools []map[string]any, emit StreamEmitter) (*AssistantPlan, bool, error) {
	params, err := c.openAIResponseToolParams(messages, tools)
	if err != nil {
		return nil, false, err
	}
	stream := c.openai.Responses.NewStreaming(ctx, params)
	defer stream.Close()
	assembler := newOpenAIResponseStreamAssembler(c.provider, c.model, emit)
	for stream.Next() {
		if err := assembler.accept(stream.Current().RawJSON()); err != nil {
			return assembler.plan(), assembler.started, err
		}
	}
	if err := stream.Err(); err != nil {
		return nil, assembler.started, err
	}
	if !assembler.started {
		return nil, false, fmt.Errorf("ai stream returned no events")
	}
	if !assembler.terminal {
		return assembler.plan(), true, fmt.Errorf("ai stream ended before a terminal event")
	}
	plan := assembler.plan()
	if strings.TrimSpace(plan.Answer) == "" && len(plan.ToolRequests) == 0 {
		return plan, true, fmt.Errorf("openai responses api returned no visible output or tool call")
	}
	return plan, true, nil
}

type openAIResponseStreamEvent struct {
	Type        string                                  `json:"type"`
	Delta       json.RawMessage                         `json:"delta"`
	ItemID      string                                  `json:"item_id"`
	OutputIndex int64                                   `json:"output_index"`
	Arguments   string                                  `json:"arguments"`
	Text        string                                  `json:"text"`
	Refusal     string                                  `json:"refusal"`
	Message     string                                  `json:"message"`
	Item        openairesponses.ResponseOutputItemUnion `json:"item"`
	Response    openairesponses.Response                `json:"response"`
}

type openAIResponseFunctionCall struct {
	name           string
	itemID         string
	arguments      strings.Builder
	finalArguments string
}

type openAIResponseStreamAssembler struct {
	provider  string
	model     string
	emit      StreamEmitter
	started   bool
	terminal  bool
	content   strings.Builder
	reasoning strings.Builder
	usage     CompletionUsage
	toolCalls map[int64]*openAIResponseFunctionCall
}

func newOpenAIResponseStreamAssembler(provider, model string, emit StreamEmitter) *openAIResponseStreamAssembler {
	return &openAIResponseStreamAssembler{
		provider:  provider,
		model:     model,
		emit:      emit,
		toolCalls: map[int64]*openAIResponseFunctionCall{},
	}
}

func (a *openAIResponseStreamAssembler) accept(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var event openAIResponseStreamEvent
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		return err
	}
	switch event.Type {
	case "response.output_text.delta":
		a.markStarted()
		delta := openAIResponseStreamDelta(event.Delta)
		a.content.WriteString(delta)
		a.emitDelta("content_delta", delta, "")
	case "response.output_text.done":
		a.markStarted()
		a.replaceContentIfEmpty(event.Text)
	case "response.refusal.delta":
		a.markStarted()
		delta := openAIResponseStreamDelta(event.Delta)
		a.content.WriteString(delta)
		a.emitDelta("content_delta", delta, "")
	case "response.refusal.done":
		a.markStarted()
		a.replaceContentIfEmpty(event.Refusal)
	case "response.reasoning_summary_text.delta", "response.reasoning_summary.delta":
		a.markStarted()
		delta := openAIResponseStreamDelta(event.Delta)
		a.reasoning.WriteString(delta)
		a.emitDelta("reasoning_delta", delta, "")
	case "response.reasoning_summary_text.done", "response.reasoning_summary.done":
		a.markStarted()
		a.replaceReasoningIfEmpty(event.Text)
	case "response.output_item.added", "response.output_item.done":
		a.markStarted()
		a.acceptOutputItem(event.OutputIndex, event.ItemID, event.Item)
	case "response.function_call_arguments.delta":
		a.markStarted()
		delta := openAIResponseStreamDelta(event.Delta)
		call := a.toolCall(event.OutputIndex, event.ItemID)
		call.arguments.WriteString(delta)
		a.emitToolDelta(call.name, delta)
	case "response.function_call_arguments.done":
		a.markStarted()
		call := a.toolCall(event.OutputIndex, event.ItemID)
		call.finalArguments = event.Arguments
	case "response.completed", "response.incomplete":
		a.markStarted()
		a.terminal = true
		a.absorbResponse(&event.Response)
	case "response.failed":
		a.markStarted()
		a.terminal = true
		a.absorbResponse(&event.Response)
		return fmt.Errorf("openai responses stream failed: %s: %s", event.Response.Error.Code, strings.TrimSpace(event.Response.Error.Message))
	case "error":
		a.markStarted()
		a.terminal = true
		return fmt.Errorf("openai responses stream failed: %s", strings.TrimSpace(event.Message))
	default:
		if event.Type != "" {
			a.markStarted()
		}
	}
	return nil
}

func openAIResponseStreamDelta(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text
	}
	var object struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &object); err == nil {
		return object.Text
	}
	return ""
}

func (a *openAIResponseStreamAssembler) acceptOutputItem(index int64, itemID string, item openairesponses.ResponseOutputItemUnion) {
	if item.Type != "function_call" {
		return
	}
	call := a.toolCall(index, firstNonEmpty(item.ID, itemID))
	if strings.TrimSpace(item.Name) != "" {
		call.name = item.Name
	}
	if item.Arguments != "" {
		call.finalArguments = item.Arguments
	}
}

func (a *openAIResponseStreamAssembler) absorbResponse(response *openairesponses.Response) {
	if response == nil {
		return
	}
	if text := openAIResponseVisibleText(response.Output); strings.TrimSpace(text) != "" && text != a.content.String() {
		a.content.Reset()
		a.content.WriteString(text)
	}
	if summary := openAIResponseReasoningSummary(response.Output); strings.TrimSpace(summary) != "" && summary != a.reasoning.String() {
		a.reasoning.Reset()
		a.reasoning.WriteString(summary)
	}
	for index, item := range response.Output {
		a.acceptOutputItem(int64(index), item.ID, item)
	}
	a.usage = openAIResponseUsage(response.Usage)
}

func (a *openAIResponseStreamAssembler) replaceContentIfEmpty(text string) {
	if a.content.Len() == 0 && text != "" {
		a.content.WriteString(text)
	}
}

func (a *openAIResponseStreamAssembler) replaceReasoningIfEmpty(text string) {
	if a.reasoning.Len() == 0 && text != "" {
		a.reasoning.WriteString(text)
	}
}

func (a *openAIResponseStreamAssembler) toolCall(index int64, itemID string) *openAIResponseFunctionCall {
	call := a.toolCalls[index]
	if call == nil {
		call = &openAIResponseFunctionCall{}
		a.toolCalls[index] = call
	}
	if itemID != "" {
		call.itemID = itemID
	}
	return call
}

func (a *openAIResponseStreamAssembler) completion() *CompletionResult {
	return &CompletionResult{
		Content:          strings.TrimSpace(a.content.String()),
		ReasoningSummary: sanitizeAssistantReasoningSummary(a.reasoning.String()),
		Provider:         a.provider,
		Model:            a.model,
		Usage:            a.usage,
	}
}

func (a *openAIResponseStreamAssembler) plan() *AssistantPlan {
	result := a.completion()
	plan := parseAssistantPlan(result.Content)
	requests := a.toolRequests()
	if len(requests) > 0 {
		plan.ToolRequests = requests
		plan.Answer = result.Content
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

func (a *openAIResponseStreamAssembler) toolRequests() []AssistantToolRequest {
	indexes := make([]int64, 0, len(a.toolCalls))
	for index := range a.toolCalls {
		indexes = append(indexes, index)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	requests := make([]AssistantToolRequest, 0, len(indexes))
	for _, index := range indexes {
		call := a.toolCalls[index]
		if call == nil || strings.TrimSpace(call.name) == "" {
			continue
		}
		arguments := call.finalArguments
		if arguments == "" {
			arguments = call.arguments.String()
		}
		args, err := decodeOpenAIToolArguments(call.name, arguments)
		if err != nil {
			args = map[string]any{"raw_arguments": arguments}
		}
		requests = append(requests, AssistantToolRequest{Name: call.name, Args: args})
	}
	return requests
}

func (a *openAIResponseStreamAssembler) markStarted() {
	if a.started {
		return
	}
	a.started = true
	a.emitEvent(AssistantTraceEvent{Type: "provider_response_start", Provider: a.provider, Model: a.model})
}

func (a *openAIResponseStreamAssembler) emitDelta(kind, delta, tool string) {
	if delta == "" {
		return
	}
	a.emitEvent(AssistantTraceEvent{Type: kind, Message: delta, ToolName: tool, Provider: a.provider, Model: a.model})
}

func (a *openAIResponseStreamAssembler) emitToolDelta(name, argsDelta string) {
	if strings.TrimSpace(name) == "" && strings.TrimSpace(argsDelta) == "" {
		return
	}
	a.emitEvent(AssistantTraceEvent{Type: "tool_call_delta", Message: argsDelta, ToolName: name, Provider: a.provider, Model: a.model})
}

func (a *openAIResponseStreamAssembler) emitEvent(event AssistantTraceEvent) {
	if a.emit != nil {
		a.emit(event)
	}
}
