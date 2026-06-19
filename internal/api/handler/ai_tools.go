package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

type aiToolExecutePayload struct {
	Name       string         `json:"name"`
	Args       map[string]any `json:"args"`
	ApprovalID string         `json:"approval_id"`
}

func (h *Handler) AITools(w http.ResponseWriter, _ *http.Request) {
	tools := h.aiAssistantRegistry().List()
	out := make([]map[string]any, 0, len(tools))
	for _, tool := range tools {
		out = append(out, aiToolView(tool))
	}
	writeData(w, out)
}

func (h *Handler) ExecuteAITool(w http.ResponseWriter, r *http.Request) {
	var req aiToolExecutePayload
	if !decode(w, r, &req) {
		return
	}
	call, err := h.executeAssistantTool(r.Context(), req.Name, req.Args, req.ApprovalID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "AI_TOOL_ERROR", err.Error())
		return
	}
	writeData(w, call)
}

func (h *Handler) ApproveAIApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	approval, err := h.aiAssistant().Approve(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "AI_APPROVAL_ERROR", err.Error())
		return
	}
	writeData(w, approval)
}

func (h *Handler) RejectAIApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	approval, err := h.aiAssistant().Reject(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, "AI_APPROVAL_ERROR", err.Error())
		return
	}
	writeData(w, approval)
}

func (h *Handler) aiAssistant() *ai.Assistant {
	return ai.NewAssistant(h.aiAssistantRegistry(), h.AssistantApprovals)
}

func (h *Handler) aiAssistantRegistry() *ai.Registry {
	registry := ai.NewDefaultRegistry(h.Config)
	registry.Register(recentSecurityEventsTool{Sink: h.Sink})
	registry.Register(knowledgeBaseTool{Config: h.Config})
	registry.Register(setBotChallengeTool{Handler: h})
	registry.Register(setProtectionLevelTool{Handler: h})
	return registry
}

func (h *Handler) executeAssistantTool(ctx context.Context, name string, args map[string]any, approvalID string) (ai.AssistantToolCall, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ai.AssistantToolCall{}, fmt.Errorf("tool name is required")
	}
	assistant := h.aiAssistant()
	tool, ok := h.aiAssistantRegistry().Get(name)
	if !ok {
		return ai.AssistantToolCall{}, fmt.Errorf("tool %q not found", name)
	}
	execution, err := assistant.ExecuteTool(ctx, name, args, approvalID)
	call := ai.AssistantToolCall{
		Name:        tool.Name(),
		Description: tool.Description(),
		Sensitivity: ai.SensitivityName(tool.Sensitivity()),
		Args:        args,
	}
	if err != nil {
		call.Error = err.Error()
		return call, err
	}
	if execution != nil {
		call.Result = execution.Result
		call.Approval = execution.Approval
	}
	return call, nil
}

func aiToolView(tool ai.Tool) map[string]any {
	return map[string]any{
		"name":        tool.Name(),
		"description": tool.Description(),
		"sensitivity": ai.SensitivityName(tool.Sensitivity()),
		"parameters":  tool.Parameters(),
	}
}

type recentSecurityEventsTool struct {
	Sink storage.LogSink
}

func (recentSecurityEventsTool) Name() string {
	return "recent_security_events"
}

func (recentSecurityEventsTool) Description() string {
	return "Read recent real CheeseWAF security events from the log sink."
}

func (recentSecurityEventsTool) Sensitivity() ai.ToolSensitivity {
	return ai.ReadOnly
}

func (recentSecurityEventsTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
		},
	}
}

func (t recentSecurityEventsTool) Execute(ctx context.Context, args map[string]any) (*ai.ToolResult, error) {
	if t.Sink == nil {
		return &ai.ToolResult{Success: true, Output: "[]"}, nil
	}
	limit := intArg(args, "limit", 10)
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	entries, _, err := t.Sink.Query(ctx, storage.LogFilter{Limit: limit * 4})
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, limit)
	for _, entry := range entries {
		if !assistantSecurityEvent(entry) {
			continue
		}
		out = append(out, map[string]any{
			"id":        entry.ID,
			"trace_id":  entry.TraceID,
			"time":      entry.Timestamp,
			"client_ip": entry.ClientIP,
			"action":    entry.Action,
			"category":  entry.Category,
			"severity":  entry.Severity,
			"uri":       entry.URI,
			"country":   entry.Country,
		})
		if len(out) >= limit {
			break
		}
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return &ai.ToolResult{Success: true, Output: string(raw)}, nil
}

type knowledgeBaseTool struct {
	Config *config.Config
}

func (knowledgeBaseTool) Name() string {
	return "knowledge_base"
}

func (knowledgeBaseTool) Description() string {
	return "Search built-in CheeseWAF product and WAF operation knowledge snippets. Read-only."
}

func (knowledgeBaseTool) Sensitivity() ai.ToolSensitivity {
	return ai.ReadOnly
}

func (knowledgeBaseTool) Parameters() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"query"},
		"properties": map[string]any{
			"query": map[string]any{"type": "string", "minLength": 1},
			"limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
		},
	}
}

func (t knowledgeBaseTool) Execute(_ context.Context, args map[string]any) (*ai.ToolResult, error) {
	cfg := config.Default().AI.Knowledge
	if t.Config != nil {
		cfg = t.Config.AI.Knowledge
	}
	query, _ := stringArg(args, "query")
	limit := intArg(args, "limit", cfg.MaxSnippets)
	output := ai.NewKnowledgeBase(cfg).SearchJSON(query, limit)
	return &ai.ToolResult{Success: true, Output: output}, nil
}

type setBotChallengeTool struct {
	Handler *Handler
}

func (setBotChallengeTool) Name() string {
	return "set_bot_challenge"
}

func (setBotChallengeTool) Description() string {
	return "Update Bot/CC challenge switches such as JS Challenge, CAPTCHA, and CAPTCHA type. Requires approval."
}

func (setBotChallengeTool) Sensitivity() ai.ToolSensitivity {
	return ai.Modify
}

func (setBotChallengeTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"enabled":      map[string]any{"type": "boolean"},
			"js_challenge": map[string]any{"type": "boolean"},
			"captcha":      map[string]any{"type": "boolean"},
			"captcha_type": map[string]any{"type": "string", "enum": []string{"pow", "image", "slider"}},
			"reason":       map[string]any{"type": "string"},
		},
	}
}

func (t setBotChallengeTool) Preview(_ context.Context, args map[string]any) (string, error) {
	before, after, err := t.nextBotConfig(args)
	if err != nil {
		return "", err
	}
	return diffJSON(before, after)
}

func (t setBotChallengeTool) Execute(_ context.Context, args map[string]any) (*ai.ToolResult, error) {
	before, after, err := t.nextBotConfig(args)
	if err != nil {
		return nil, err
	}
	if t.Handler == nil || t.Handler.Config == nil {
		return nil, fmt.Errorf("handler config is nil")
	}
	t.Handler.Config.Protection.Bot = after
	if err := t.Handler.persistConfig(); err != nil {
		return nil, err
	}
	if err := t.Handler.notifyProtectionChanged(); err != nil {
		return nil, err
	}
	diff, _ := diffJSON(before, after)
	return &ai.ToolResult{Success: true, Output: "bot challenge policy updated", Diff: diff}, nil
}

func (t setBotChallengeTool) nextBotConfig(args map[string]any) (config.BotProtectionConfig, config.BotProtectionConfig, error) {
	if t.Handler == nil || t.Handler.Config == nil {
		return config.BotProtectionConfig{}, config.BotProtectionConfig{}, fmt.Errorf("handler config is nil")
	}
	before := t.Handler.Config.Protection.Bot
	after := before
	if value, ok := boolArg(args, "enabled"); ok {
		after.Enabled = value
	}
	if value, ok := boolArg(args, "js_challenge"); ok {
		after.JSChallenge = value
	}
	if value, ok := boolArg(args, "captcha"); ok {
		after.CAPTCHA = value
	}
	if raw, ok := stringArg(args, "captcha_type"); ok {
		captchaType := strings.ToLower(strings.TrimSpace(raw))
		switch captchaType {
		case "pow", "image", "slider":
			after.CAPTCHAType = captchaType
		default:
			return before, after, fmt.Errorf("unsupported captcha_type %q", raw)
		}
	}
	return before, after, nil
}

type setProtectionLevelTool struct {
	Handler *Handler
}

func (setProtectionLevelTool) Name() string {
	return "set_protection_level"
}

func (setProtectionLevelTool) Description() string {
	return "Update one global protection level: web_attack, api_security, bot_cc, or threat_intel. Requires approval."
}

func (setProtectionLevelTool) Sensitivity() ai.ToolSensitivity {
	return ai.Modify
}

func (setProtectionLevelTool) Parameters() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"area", "level"},
		"properties": map[string]any{
			"area":   map[string]any{"type": "string", "enum": []string{"web_attack", "api_security", "bot_cc", "threat_intel"}},
			"level":  map[string]any{"type": "string", "enum": []string{"off", "low", "smart", "high", "strict"}},
			"reason": map[string]any{"type": "string"},
		},
	}
}

func (t setProtectionLevelTool) Preview(_ context.Context, args map[string]any) (string, error) {
	before, after, err := t.nextPolicy(args)
	if err != nil {
		return "", err
	}
	return diffJSON(before, after)
}

func (t setProtectionLevelTool) Execute(_ context.Context, args map[string]any) (*ai.ToolResult, error) {
	before, after, err := t.nextPolicy(args)
	if err != nil {
		return nil, err
	}
	t.Handler.Config.Protection.Policy = after
	if err := t.Handler.persistConfig(); err != nil {
		return nil, err
	}
	if err := t.Handler.notifyProtectionChanged(); err != nil {
		return nil, err
	}
	diff, _ := diffJSON(before, after)
	return &ai.ToolResult{Success: true, Output: "global protection level updated", Diff: diff}, nil
}

func (t setProtectionLevelTool) nextPolicy(args map[string]any) (config.ProtectionPolicyConfig, config.ProtectionPolicyConfig, error) {
	if t.Handler == nil || t.Handler.Config == nil {
		return config.ProtectionPolicyConfig{}, config.ProtectionPolicyConfig{}, fmt.Errorf("handler config is nil")
	}
	area, ok := stringArg(args, "area")
	if !ok {
		return config.ProtectionPolicyConfig{}, config.ProtectionPolicyConfig{}, fmt.Errorf("area is required")
	}
	level, ok := stringArg(args, "level")
	if !ok {
		return config.ProtectionPolicyConfig{}, config.ProtectionPolicyConfig{}, fmt.Errorf("level is required")
	}
	area = normalizeProtectionArea(area)
	level = normalizeProtectionLevel(level)
	if !config.IsProtectionLevel(level) || level == "" {
		return config.ProtectionPolicyConfig{}, config.ProtectionPolicyConfig{}, fmt.Errorf("invalid protection level %q", level)
	}
	before := t.Handler.Config.Protection.Policy.WithDefaults(config.DefaultProtectionPolicy())
	after := before
	switch area {
	case "web_attack":
		after.WebAttack = level
	case "api_security":
		after.APISecurity = level
	case "bot_cc":
		after.BotCC = level
	case "threat_intel":
		after.ThreatIntel = level
	default:
		return before, after, fmt.Errorf("invalid protection area %q", area)
	}
	return before, after, nil
}

func assistantSecurityEvent(entry storage.LogEntry) bool {
	return strings.TrimSpace(entry.Category) != "" || entry.Action == "block" || entry.Action == "challenge" || entry.Action == "log"
}

func diffJSON(before, after any) (string, error) {
	raw, err := json.MarshalIndent(map[string]any{"before": before, "after": after}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func intArg(args map[string]any, key string, fallback int) int {
	value, ok := args[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case float64:
		return int(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed)
		}
	}
	return fallback
}

func boolArg(args map[string]any, key string) (bool, bool) {
	value, ok := args[key]
	if !ok {
		return false, false
	}
	typed, ok := value.(bool)
	return typed, ok
}

func stringArg(args map[string]any, key string) (string, bool) {
	value, ok := args[key]
	if !ok {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return typed, true
	default:
		return fmt.Sprint(typed), true
	}
}

func normalizeProtectionArea(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "web", "web_attack", "web attack", "网页攻击", "web攻击":
		return "web_attack"
	case "api", "api_security", "api security", "api安全":
		return "api_security"
	case "bot", "bot_cc", "bot/cc", "cc", "botcc", "bot防护":
		return "bot_cc"
	case "intel", "threat", "threat_intel", "threat intel", "威胁情报":
		return "threat_intel"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeProtectionLevel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "关闭", "停用":
		return config.ProtectionLevelOff
	case "低", "低误报":
		return config.ProtectionLevelLow
	case "智能", "默认":
		return config.ProtectionLevelSmart
	case "高":
		return config.ProtectionLevelHigh
	case "严格", "最严":
		return config.ProtectionLevelStrict
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}
