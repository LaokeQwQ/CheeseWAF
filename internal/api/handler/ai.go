package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type aiConfigPayload struct {
	Enabled   bool   `json:"enabled"`
	Provider  string `json:"provider"`
	APIBase   string `json:"api_base"`
	APIKey    string `json:"api_key,omitempty"`
	APIKeySet bool   `json:"api_key_set"`
	Model     string `json:"model"`
	Async     bool   `json:"async"`
}

type aiEventsAnalyzePayload struct {
	Limit    int    `json:"limit"`
	Action   string `json:"action"`
	Category string `json:"category"`
	ClientIP string `json:"client_ip"`
	TraceID  string `json:"trace_id"`
	Start    string `json:"start"`
	End      string `json:"end"`
	Language string `json:"language"`
}

type aiAnalyzeLogPayload struct {
	storage.LogEntry
	Reference string            `json:"reference"`
	Event     *storage.LogEntry `json:"event"`
	Language  string            `json:"language"`
}

type aiAssistantPayload struct {
	Message  string `json:"message"`
	Limit    int    `json:"limit"`
	Language string `json:"language"`
}

func (h *Handler) AIConfig(w http.ResponseWriter, _ *http.Request) {
	writeData(w, aiConfigView(h.Config.AI))
}

func (h *Handler) UpdateAIConfig(w http.ResponseWriter, r *http.Request) {
	var req aiConfigPayload
	if !decode(w, r, &req) {
		return
	}
	next := config.AIConfig{
		Enabled:      req.Enabled,
		Provider:     req.Provider,
		APIBase:      req.APIBase,
		APIKey:       req.APIKey,
		APIKeyHeader: h.Config.AI.APIKeyHeader,
		Model:        req.Model,
		Async:        req.Async,
	}
	if next.Provider == "" {
		next.Provider = h.Config.AI.Provider
	}
	if next.Provider == "" {
		next.Provider = "openai"
	}
	if next.APIKey == "" {
		next.APIKey = h.Config.AI.APIKey
	}
	h.Config.AI = next
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, aiConfigView(h.Config.AI))
}

func (h *Handler) TestAIConnection(w http.ResponseWriter, r *http.Request) {
	if err := ai.TestConnection(r.Context(), h.Config.AI); err != nil {
		writeError(w, http.StatusBadGateway, "AI_CONNECTION_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"ok": true})
}

func (h *Handler) AnalyzeLog(w http.ResponseWriter, r *http.Request) {
	var req aiAnalyzeLogPayload
	if !decode(w, r, &req) {
		return
	}
	entry, status, code, err := h.resolveAnalyzeLogEntry(r, req)
	if err != nil {
		writeError(w, status, code, err.Error())
		return
	}
	analysis, err := ai.AnalyzeLogWithLanguage(r.Context(), h.aiClient(), entry, req.Language)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
		return
	}
	writeData(w, analysis)
}

func (h *Handler) resolveAnalyzeLogEntry(r *http.Request, req aiAnalyzeLogPayload) (storage.LogEntry, int, string, error) {
	if ref := strings.TrimSpace(req.Reference); ref != "" {
		entry, ok, err := h.lookupLogEvent(r, ref)
		if err != nil {
			return storage.LogEntry{}, http.StatusInternalServerError, "LOG_QUERY_ERROR", err
		}
		if !ok {
			return storage.LogEntry{}, http.StatusNotFound, "LOG_NOT_FOUND", errLogNotFound(ref)
		}
		return entry, http.StatusOK, "", nil
	}
	if req.Event != nil {
		return h.resolveLegacyLogEntry(r, *req.Event)
	}
	return h.resolveLegacyLogEntry(r, req.LogEntry)
}

func (h *Handler) resolveLegacyLogEntry(r *http.Request, entry storage.LogEntry) (storage.LogEntry, int, string, error) {
	if !hasLogEvidence(entry) {
		return storage.LogEntry{}, http.StatusBadRequest, "BAD_REQUEST", errLogReferenceRequired()
	}
	ref := firstNonEmpty(entry.TraceID, entry.ID)
	if ref != "" && h.Sink != nil {
		if stored, ok, err := h.lookupLogEvent(r, ref); err != nil {
			return storage.LogEntry{}, http.StatusInternalServerError, "LOG_QUERY_ERROR", err
		} else if ok {
			return stored, http.StatusOK, "", nil
		}
	}
	return entry, http.StatusOK, "", nil
}

func (h *Handler) lookupLogEvent(r *http.Request, reference string) (storage.LogEntry, bool, error) {
	if h.Sink == nil {
		return storage.LogEntry{}, false, nil
	}
	entries, _, err := h.Sink.Query(r.Context(), storage.LogFilter{TraceID: reference, Limit: 10})
	if err != nil {
		return storage.LogEntry{}, false, err
	}
	if entry, ok := pickLogEvent(entries, reference); ok {
		return entry, true, nil
	}
	entries, _, err = h.Sink.Query(r.Context(), storage.LogFilter{Limit: 500})
	if err != nil {
		return storage.LogEntry{}, false, err
	}
	entry, ok := pickLogEvent(entries, reference)
	return entry, ok, nil
}

func pickLogEvent(entries []storage.LogEntry, reference string) (storage.LogEntry, bool) {
	for _, entry := range entries {
		if entry.TraceID == reference || entry.ID == reference {
			return entry, true
		}
	}
	if len(entries) > 0 && entries[0].TraceID == reference {
		return entries[0], true
	}
	return storage.LogEntry{}, false
}

func hasLogEvidence(entry storage.LogEntry) bool {
	return firstNonEmpty(entry.ID, entry.TraceID, entry.Action, entry.Category, entry.URI, entry.Message, entry.Payload, entry.ClientIP) != ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type logReferenceError string

func (e logReferenceError) Error() string { return string(e) }

func errLogNotFound(reference string) error {
	return logReferenceError("log event not found: " + reference)
}

func errLogReferenceRequired() error {
	return logReferenceError("reference or log event is required")
}

func (h *Handler) AnalyzeEvents(w http.ResponseWriter, r *http.Request) {
	var req aiEventsAnalyzePayload
	if !decode(w, r, &req) {
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	startTime, ok := parsePayloadTime(w, req.Start, "start")
	if !ok {
		return
	}
	endTime, ok := parsePayloadTime(w, req.End, "end")
	if !ok {
		return
	}
	if !startTime.IsZero() && !endTime.IsZero() && endTime.Before(startTime) {
		writeError(w, http.StatusBadRequest, "BAD_TIME_RANGE", "end must be after start")
		return
	}
	entries := h.queryLogs(r, storage.LogFilter{
		Limit:     limit,
		Action:    req.Action,
		Category:  req.Category,
		ClientIP:  req.ClientIP,
		TraceID:   req.TraceID,
		StartTime: startTime,
		EndTime:   endTime,
	})
	analyses, err := ai.AnalyzeEventsWithLanguage(r.Context(), h.aiClient(), entries, req.Language)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"items": analyses, "total": len(analyses)})
}

func parsePayloadTime(w http.ResponseWriter, raw string, name string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, true
	}
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_TIME_RANGE", name+" must be RFC3339")
		return time.Time{}, false
	}
	return value, true
}

func (h *Handler) AIAssistant(w http.ResponseWriter, r *http.Request) {
	var req aiAssistantPayload
	if !decode(w, r, &req) {
		return
	}
	reply, err := h.runAssistantAgent(r.Context(), req, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ASSISTANT_FAILED", err.Error())
		return
	}
	writeData(w, reply)
}

func (h *Handler) AIAssistantStream(w http.ResponseWriter, r *http.Request) {
	var req aiAssistantPayload
	if !decode(w, r, &req) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		reply, err := h.runAssistantAgent(r.Context(), req, nil)
		if err != nil {
			writeError(w, http.StatusBadGateway, "AI_ASSISTANT_FAILED", err.Error())
			return
		}
		w.Header().Set("X-CheeseWAF-Stream-Fallback", "json")
		writeData(w, reply)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	emit := func(event ai.AssistantTraceEvent) {
		writeAssistantSSE(w, flusher, "trace", event)
	}
	reply, err := h.runAssistantAgent(r.Context(), req, emit)
	if err != nil {
		writeAssistantSSE(w, flusher, "error", map[string]any{"message": err.Error()})
		return
	}
	writeAssistantSSE(w, flusher, "done", reply)
}

func (h *Handler) runAssistantAgent(ctx context.Context, req aiAssistantPayload, emit func(ai.AssistantTraceEvent)) (*ai.AssistantReply, error) {
	if strings.TrimSpace(req.Message) == "" {
		return nil, fmt.Errorf("message is required")
	}
	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	trace := make([]ai.AssistantTraceEvent, 0, 8)
	record := func(event ai.AssistantTraceEvent) {
		event.At = time.Now().UTC().Format(time.RFC3339Nano)
		trace = append(trace, event)
		if emit != nil {
			emit(event)
		}
	}
	client := h.aiClient()
	var reply *ai.AssistantReply
	if client == nil {
		record(ai.AssistantTraceEvent{Type: "local_router", Message: localizedTraceMessage(req.Language, "AI 未启用或未配置密钥，使用本地工具路由；不会伪装成模型原生工具调用。", "AI is disabled or missing a key; using the local tool router without pretending it is native model tool calling.")})
		entries := h.queryLogsFromContext(ctx, storage.LogFilter{Limit: limit})
		runtime := map[string]any{"snapshot": h.monitorSnapshotFromContext(ctx)}
		var err error
		reply, err = ai.AnswerAssistantWithLanguage(ctx, nil, req.Message, entries, runtime, req.Language)
		if err != nil {
			return nil, err
		}
		reply.ToolExecutions = append(reply.ToolExecutions, h.executeAssistantToolRequests(ctx, intentsToToolRequests(h.assistantToolIntents(req.Message)), record)...)
		if len(reply.ToolExecutions) > 0 {
			reply.Answer = appendToolExecutionSummary(reply.Answer, reply.ToolExecutions)
		}
		reply.Trace = trace
		return reply, nil
	}
	registry := h.aiAssistantRegistry()
	toolDefinitions := registry.ListForLLM()
	record(ai.AssistantTraceEvent{Type: "planning_start", Message: localizedTraceMessage(req.Language, "正在让模型通过原生工具接口选择需要调用的 CheeseWAF 工具。", "Asking the model to choose CheeseWAF tools through the native tool interface.")})
	plan, err := ai.PlanAssistantToolCalls(ctx, client, req.Message, req.Language, toolDefinitions)
	if err != nil {
		requests := intentsToToolRequests(h.assistantToolIntents(req.Message))
		if len(requests) > 0 {
			record(ai.AssistantTraceEvent{Type: "planning_error", Message: localizedTraceMessage(req.Language, "模型工具规划失败，转入本地保守意图路由。", "Model tool planning failed; switching to the conservative local intent router."), Error: err.Error()})
			calls := h.executeAssistantToolRequests(ctx, requests, record)
			reply, fallbackErr := ai.AnswerAssistantWithToolResults(ctx, nil, req.Message, req.Language, toolDefinitions, calls)
			if fallbackErr == nil {
				reply.Answer = appendProviderFailure(reply.Answer, req.Language, err)
				reply.Trace = trace
				return reply, nil
			}
		}
		return nil, err
	}
	record(ai.AssistantTraceEvent{
		Type:         "planning_done",
		Message:      localizedPlanningMessage(req.Language, len(plan.ToolRequests), plan.Mode),
		Provider:     plan.Provider,
		Model:        plan.Model,
		Mode:         plan.Mode,
		InputTokens:  plan.InputTokens,
		OutputTokens: plan.OutputTokens,
		TotalTokens:  plan.TotalTokens,
	})
	requests := plan.ToolRequests
	if len(requests) == 0 {
		requests = intentsToToolRequests(h.assistantToolIntents(req.Message))
		if len(requests) > 0 {
			record(ai.AssistantTraceEvent{Type: "local_intent_tools", Message: localizedTraceMessage(req.Language, "模型没有主动请求工具，本地路由根据明确意图补充了工具请求。", "The model did not request tools; local routing added tool requests from explicit operator intent.")})
		}
	}
	if len(requests) == 0 {
		reply = &ai.AssistantReply{
			Answer:       plan.Answer,
			AIUsed:       true,
			Provider:     plan.Provider,
			Model:        plan.Model,
			InputTokens:  plan.InputTokens,
			OutputTokens: plan.OutputTokens,
			TotalTokens:  plan.TotalTokens,
		}
		reply.Trace = trace
		return reply, nil
	}
	calls := h.executeAssistantToolRequests(ctx, requests, record)
	record(ai.AssistantTraceEvent{Type: "final_start", Message: localizedTraceMessage(req.Language, "工具 observation 已返回，正在让模型基于这些真实结果生成最终回答。", "Tool observations have returned; asking the model to produce the final answer from those real results.")})
	reply, err = ai.AnswerAssistantWithToolResults(ctx, client, req.Message, req.Language, toolDefinitions, calls)
	if err != nil {
		providerErr := err
		record(ai.AssistantTraceEvent{Type: "final_error", Message: localizedTraceMessage(req.Language, "模型最终总结失败，保留真实工具结果并返回本地摘要。", "Model final summarization failed; keeping real tool results and returning a local summary."), Error: providerErr.Error()})
		reply, err = ai.AnswerAssistantWithToolResults(ctx, nil, req.Message, req.Language, toolDefinitions, calls)
		if err != nil {
			return nil, err
		}
		reply.Answer = appendProviderFailure(reply.Answer, req.Language, providerErr)
		reply.Trace = trace
		return reply, nil
	}
	reply.InputTokens += plan.InputTokens
	reply.OutputTokens += plan.OutputTokens
	reply.TotalTokens += plan.TotalTokens
	if reply.Provider == "" {
		reply.Provider = plan.Provider
	}
	if reply.Model == "" {
		reply.Model = plan.Model
	}
	record(ai.AssistantTraceEvent{
		Type:         "final_done",
		Message:      localizedTraceMessage(req.Language, "最终回答已生成。", "Final answer generated."),
		Provider:     reply.Provider,
		Model:        reply.Model,
		InputTokens:  reply.InputTokens,
		OutputTokens: reply.OutputTokens,
		TotalTokens:  reply.TotalTokens,
	})
	reply.Trace = trace
	return reply, nil
}

type assistantToolIntent struct {
	Name string
	Args map[string]any
}

func intentsToToolRequests(intents []assistantToolIntent) []ai.AssistantToolRequest {
	out := make([]ai.AssistantToolRequest, 0, len(intents))
	for _, intent := range intents {
		out = append(out, ai.AssistantToolRequest{Name: intent.Name, Args: intent.Args})
	}
	return out
}

func (h *Handler) executeAssistantToolRequests(ctx context.Context, requests []ai.AssistantToolRequest, emit func(ai.AssistantTraceEvent)) []ai.AssistantToolCall {
	calls := make([]ai.AssistantToolCall, 0, len(requests))
	for _, request := range requests {
		if emit != nil {
			emit(ai.AssistantTraceEvent{Type: "tool_call", Message: "tool_call: " + request.Name, ToolName: request.Name, Args: request.Args})
		}
		call, err := h.executeAssistantTool(ctx, request.Name, request.Args, "")
		if err != nil {
			if call.Name == "" {
				call.Name = request.Name
				call.Args = request.Args
				call.Sensitivity = "unknown"
			}
			call.Error = err.Error()
		}
		if emit != nil {
			event := ai.AssistantTraceEvent{ToolName: call.Name, Args: call.Args, Result: call.Result, Approval: call.Approval, Error: call.Error}
			switch {
			case call.Approval != nil:
				event.Type = "approval_required"
				event.Message = "approval_required: " + call.Name
			case call.Error != "":
				event.Type = "tool_error"
				event.Message = "tool_error: " + call.Name
			default:
				event.Type = "tool_result"
				event.Message = "tool_result: " + call.Name
			}
			emit(event)
		}
		calls = append(calls, call)
	}
	return calls
}

func (h *Handler) assistantToolIntents(message string) []assistantToolIntent {
	normalized := strings.ToLower(strings.TrimSpace(message))
	if normalized == "" {
		return nil
	}
	var intents []assistantToolIntent
	if containsAny(normalized, "系统摘要", "系统状态", "配置摘要", "runtime", "status", "summary") {
		intents = append(intents, assistantToolIntent{Name: "system_summary", Args: map[string]any{}})
	}
	if containsAny(normalized, "最近事件", "安全事件", "攻击事件", "拦截事件", "recent events", "security events") {
		intents = append(intents, assistantToolIntent{Name: "recent_security_events", Args: map[string]any{"limit": 10}})
	}
	if containsAny(normalized, "js challenge", "js挑战", "bot验证", "bot 验证", "验证码", "captcha", "滑块") &&
		containsAny(normalized, "开启", "打开", "启用", "关闭", "停用", "改成", "设置", "set", "enable", "disable") {
		args := map[string]any{}
		if containsAny(normalized, "开启", "打开", "启用", "enable") {
			args["enabled"] = true
		}
		if containsAny(normalized, "关闭", "停用", "disable") {
			args["enabled"] = false
		}
		if containsAny(normalized, "js challenge", "js挑战") {
			args["js_challenge"] = !containsAny(normalized, "关闭", "停用", "disable")
		}
		if containsAny(normalized, "验证码", "captcha", "滑块", "图像验证码", "image captcha") {
			args["captcha"] = !containsAny(normalized, "关闭", "停用", "disable")
		}
		if containsAny(normalized, "slider", "滑块") {
			args["captcha_type"] = "slider"
		} else if containsAny(normalized, "image", "图像") {
			args["captcha_type"] = "image"
		} else if containsAny(normalized, "pow", "altcha") {
			args["captcha_type"] = "pow"
		}
		if len(args) > 0 {
			intents = append(intents, assistantToolIntent{Name: "set_bot_challenge", Args: args})
		}
	}
	if area, level, ok := parseProtectionLevelIntent(normalized); ok {
		intents = append(intents, assistantToolIntent{Name: "set_protection_level", Args: map[string]any{"area": area, "level": level}})
	}
	return intents
}

func parseProtectionLevelIntent(message string) (string, string, bool) {
	if !containsAny(message, "防护等级", "保护等级", "protection level", "防护级别") ||
		!containsAny(message, "设置", "改成", "切到", "调到", "set", "change") {
		return "", "", false
	}
	area := ""
	switch {
	case containsAny(message, "web", "网页", "web攻击"):
		area = "web_attack"
	case containsAny(message, "api"):
		area = "api_security"
	case containsAny(message, "bot", "cc"):
		area = "bot_cc"
	case containsAny(message, "威胁情报", "intel", "threat"):
		area = "threat_intel"
	}
	level := ""
	switch {
	case containsAny(message, "关闭", "off"):
		level = "off"
	case containsAny(message, "严格", "strict"):
		level = "strict"
	case containsAny(message, "高", "high"):
		level = "high"
	case containsAny(message, "低", "low"):
		level = "low"
	case containsAny(message, "智能", "smart", "默认"):
		level = "smart"
	}
	return area, level, area != "" && level != ""
}

func appendToolExecutionSummary(answer string, calls []ai.AssistantToolCall) string {
	var readCount, approvalCount, executedCount int
	for _, call := range calls {
		if call.Approval != nil {
			approvalCount++
			continue
		}
		if call.Result != nil && call.Result.Success {
			if call.Sensitivity == ai.SensitivityName(ai.ReadOnly) {
				readCount++
			} else {
				executedCount++
			}
		}
	}
	parts := make([]string, 0, 3)
	if readCount > 0 {
		parts = append(parts, "已读取 "+itoa(readCount)+" 个只读工具结果。")
	}
	if approvalCount > 0 {
		parts = append(parts, "检测到 "+itoa(approvalCount)+" 个需要审批的配置变更，请在下方审批卡确认后才会执行。")
	}
	if executedCount > 0 {
		parts = append(parts, "已执行 "+itoa(executedCount)+" 个已审批工具。")
	}
	if len(parts) == 0 {
		return answer
	}
	if strings.TrimSpace(answer) == "" {
		return strings.Join(parts, " ")
	}
	return strings.TrimSpace(answer) + "\n\n" + strings.Join(parts, " ")
}

func appendProviderFailure(answer, language string, err error) string {
	if err == nil {
		return answer
	}
	message := "AI provider request failed after tool execution. The visible tool results above are still real, but the model summary was not completed: " + err.Error()
	if strings.Contains(strings.ToLower(language), "zh") {
		message = "AI provider 在工具执行后请求失败。上方工具结果仍是真实数据，但模型总结未完成：" + err.Error()
	}
	if strings.TrimSpace(answer) == "" {
		return message
	}
	return strings.TrimSpace(answer) + "\n\n" + message
}

func localizedTraceMessage(language, zh, en string) string {
	if strings.Contains(strings.ToLower(language), "en") {
		return en
	}
	return zh
}

func localizedPlanningMessage(language string, calls int, mode string) string {
	if strings.Contains(strings.ToLower(language), "en") {
		if calls == 0 {
			return "The model did not request any tool calls. Mode: " + nonEmpty(mode, "unknown") + "."
		}
		return fmt.Sprintf("The model requested %d tool call(s). Mode: %s.", calls, nonEmpty(mode, "unknown"))
	}
	if calls == 0 {
		return "模型没有请求工具调用。模式：" + nonEmpty(mode, "unknown") + "。"
	}
	return fmt.Sprintf("模型请求了 %d 个工具调用。模式：%s。", calls, nonEmpty(mode, "unknown"))
}

func nonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func writeAssistantSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw, _ = json.Marshal(map[string]any{"message": err.Error()})
		event = "error"
	}
	_, _ = fmt.Fprintf(w, "event: %s\n", event)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
	flusher.Flush()
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func itoa(value int) string {
	return fmt.Sprintf("%d", value)
}

func (h *Handler) aiClient() *ai.Client {
	if h.Config.AI.Enabled && h.Config.AI.APIKey != "" {
		return ai.NewClient(h.Config.AI, nil)
	}
	return nil
}

func (h *Handler) queryLogs(r *http.Request, filter storage.LogFilter) []storage.LogEntry {
	if h.Sink == nil {
		return nil
	}
	entries, _, err := h.Sink.Query(r.Context(), filter)
	if err != nil {
		return nil
	}
	return entries
}

func aiConfigView(cfg config.AIConfig) aiConfigPayload {
	provider := cfg.Provider
	if provider == "" {
		provider = "openai"
	}
	return aiConfigPayload{
		Enabled:   cfg.Enabled,
		Provider:  provider,
		APIBase:   cfg.APIBase,
		APIKeySet: cfg.APIKey != "",
		Model:     cfg.Model,
		Async:     cfg.Async,
	}
}
