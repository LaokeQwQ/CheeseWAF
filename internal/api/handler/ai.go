package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

type aiConfigPayload struct {
	Enabled             bool                      `json:"enabled"`
	Provider            string                    `json:"provider"`
	APIBase             string                    `json:"api_base"`
	APIKey              string                    `json:"api_key,omitempty"`
	APIKeySet           bool                      `json:"api_key_set"`
	Model               string                    `json:"model"`
	Async               bool                      `json:"async"`
	AllowPrivateAPIBase bool                      `json:"allow_private_api_base"`
	Assistant           *aiModelConfigPayload     `json:"assistant,omitempty"`
	Reasoning           *aiModelConfigPayload     `json:"reasoning,omitempty"`
	SelfLearning        any                       `json:"self_learning,omitempty"`
	Knowledge           *config.AIKnowledgeConfig `json:"knowledge,omitempty"`
}

type aiModelConfigPayload struct {
	Provider            string `json:"provider"`
	APIBase             string `json:"api_base"`
	APIKey              string `json:"api_key,omitempty"`
	APIKeySet           bool   `json:"api_key_set"`
	Model               string `json:"model"`
	AllowPrivateAPIBase bool   `json:"allow_private_api_base"`
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
	Message   string `json:"message"`
	Limit     int    `json:"limit"`
	Language  string `json:"language"`
	DeepThink bool   `json:"deep_think"`
}

type aiModelsPayload struct {
	Provider            string `json:"provider"`
	APIBase             string `json:"api_base"`
	APIKey              string `json:"api_key,omitempty"`
	Target              string `json:"target,omitempty"`
	AllowPrivateAPIBase bool   `json:"allow_private_api_base"`
}

type aiTestPayload struct {
	Provider            string `json:"provider"`
	APIBase             string `json:"api_base"`
	APIKey              string `json:"api_key,omitempty"`
	Model               string `json:"model"`
	Target              string `json:"target"`
	AllowPrivateAPIBase bool   `json:"allow_private_api_base"`
}

type aiSelfLearningRunPayload struct {
	DryRun   *bool  `json:"dry_run,omitempty"`
	Language string `json:"language"`
}

const aiLongRequestTimeout = 5 * time.Minute

var (
	providerFirstEventSlowAfter     = 10 * time.Second
	providerWaitingProgressInterval = 10 * time.Second
)

type aiSelfLearningConfigView struct {
	Enabled        bool    `json:"enabled"`
	AutoApply      bool    `json:"auto_apply"`
	DryRun         bool    `json:"dry_run"`
	Interval       string  `json:"interval"`
	At             string  `json:"at"`
	MinConfidence  float64 `json:"min_confidence"`
	MinEvents      int     `json:"min_events"`
	MaxEvents      int     `json:"max_events"`
	MaxRulesPerRun int     `json:"max_rules_per_run"`
	Action         string  `json:"action"`
}

func (h *Handler) AIConfig(w http.ResponseWriter, _ *http.Request) {
	writeData(w, aiConfigView(h.Config.AI))
}

func (h *Handler) UpdateAIConfig(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req aiConfigPayload
	if !decode(w, r, &req) {
		return
	}
	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		next := candidate.AI
		next.Enabled = req.Enabled
		next.Provider = firstNonEmpty(req.Provider, next.Provider)
		next.APIBase = firstNonEmpty(req.APIBase, next.APIBase)
		next.Model = firstNonEmpty(req.Model, next.Model)
		next.Async = req.Async
		next.AllowPrivateAPIBase = req.AllowPrivateAPIBase
		if req.APIKey != "" {
			next.APIKey = req.APIKey
		}
		if next.Provider == "" {
			next.Provider = "openai"
		}
		if req.Assistant != nil {
			next.Assistant = mergeAIModelPayload(next.Assistant, *req.Assistant)
		}
		if req.Reasoning != nil {
			next.Reasoning = mergeAIModelPayload(next.Reasoning, *req.Reasoning)
		}
		next.Assistant = mergeAIModelPayload(next.Assistant, legacyAIModelPayload(next))
		next.Reasoning = mergeAIModelPayload(next.Reasoning, aiModelPayloadFromConfig(next.Assistant))
		if req.SelfLearning != nil {
			selfLearning, parseErr := parseAISelfLearningConfig(req.SelfLearning, next.SelfLearning)
			if parseErr != nil {
				return parseErr
			}
			next.SelfLearning = selfLearning
		}
		if req.Knowledge != nil {
			next.Knowledge = *req.Knowledge
		}
		if validateErr := validateAIConfigForSave(next); validateErr != nil {
			return validateErr
		}
		candidate.AI = next
		return nil
	}, nil)
	if err != nil {
		code := "CONFIG_SAVE_ERROR"
		status := http.StatusInternalServerError
		if isAIAPIBaseValidationError(err) {
			code = "AI_API_BASE_INVALID"
			status = http.StatusBadRequest
		} else if strings.Contains(err.Error(), "AI") || strings.Contains(err.Error(), "model") || strings.Contains(err.Error(), "provider") {
			code = "AI_CONFIG_INVALID"
			status = http.StatusBadRequest
		}
		writeError(w, status, code, err.Error())
		return
	}
	writeData(w, aiConfigView(committed.AI))
}

func (h *Handler) TestAIConnection(w http.ResponseWriter, r *http.Request) {
	allowLongResponseWrite(w)
	target := ""
	var cfg config.AIConfig
	if r.Body != nil && r.ContentLength != 0 {
		var req aiTestPayload
		if !decode(w, r, &req) {
			return
		}
		target = req.Target
		cfg = h.aiRuntimeConfig(target)
		cfg.Enabled = true
		if strings.TrimSpace(req.Provider) != "" {
			cfg.Provider = strings.TrimSpace(req.Provider)
		}
		if strings.TrimSpace(req.APIBase) != "" {
			cfg.APIBase = strings.TrimSpace(req.APIBase)
		}
		if strings.TrimSpace(req.APIKey) != "" {
			cfg.APIKey = strings.TrimSpace(req.APIKey)
		}
		if strings.TrimSpace(req.Model) != "" {
			cfg.Model = strings.TrimSpace(req.Model)
		}
		cfg.AllowPrivateAPIBase = req.AllowPrivateAPIBase
	} else {
		cfg = h.aiRuntimeConfig(target)
	}
	cfg.Enabled = true
	if err := validateAITestConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, aiTestValidationErrorCode(err), err.Error())
		return
	}
	if err := ai.TestConnection(r.Context(), cfg); err != nil {
		writeError(w, http.StatusBadGateway, "AI_CONNECTION_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"ok": true, "target": normalizeAITarget(target)})
}

func (h *Handler) AIModels(w http.ResponseWriter, r *http.Request) {
	allowLongResponseWrite(w)
	cfg := h.aiModelsConfigFromRequest(w, r)
	if cfg == nil {
		return
	}
	if cfg.Provider == "" {
		cfg.Provider = "openai"
	}
	if !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "AI_DISABLED", "ai is disabled")
		return
	}
	if cfg.APIKey == "" {
		writeError(w, http.StatusBadRequest, "AI_KEY_REQUIRED", "ai api key is required")
		return
	}
	if strings.TrimSpace(cfg.APIBase) == "" {
		writeError(w, http.StatusBadRequest, "AI_API_BASE_REQUIRED", "ai api base is required")
		return
	}
	if err := validateAIAPIBase(cfg.APIBase, cfg.AllowPrivateAPIBase); err != nil {
		writeError(w, http.StatusBadRequest, "AI_API_BASE_INVALID", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	models, err := ai.NewClientWithTimeout(*cfg, 45*time.Second).ListModels(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_MODELS_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"items": models, "total": len(models)})
}

func (h *Handler) aiModelsConfigFromRequest(w http.ResponseWriter, r *http.Request) *config.AIConfig {
	target := ""
	cfg := h.Config.AI.AssistantRuntimeConfig()
	cfg.Enabled = true
	if r.Method == http.MethodGet {
		return &cfg
	}
	var req aiModelsPayload
	if !decode(w, r, &req) {
		return nil
	}
	target = req.Target
	cfg = h.aiRuntimeConfig(target)
	cfg.Enabled = true
	if strings.TrimSpace(req.Provider) != "" {
		cfg.Provider = strings.TrimSpace(req.Provider)
	}
	if strings.TrimSpace(req.APIBase) != "" {
		cfg.APIBase = strings.TrimSpace(req.APIBase)
	}
	if strings.TrimSpace(req.APIKey) != "" {
		cfg.APIKey = strings.TrimSpace(req.APIKey)
	}
	cfg.AllowPrivateAPIBase = req.AllowPrivateAPIBase
	return &cfg
}

func validateAIAPIBase(raw string, allowPrivate bool) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid ai api base: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("ai api base must start with http:// or https://")
	}
	if parsed.Host == "" {
		return fmt.Errorf("ai api base host is required")
	}
	if allowPrivate {
		return nil
	}
	host := parsed.Hostname()
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("ai api base host is required")
	}
	if isPrivateAIAPIBaseHost(host) {
		return fmt.Errorf("ai api base points to a private, loopback, link-local, or unspecified host; enable allow_private_api_base only for trusted local model gateways")
	}
	return nil
}

func isPrivateAIAPIBaseHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	switch normalized {
	case "", "localhost", "localhost.localdomain":
		return true
	}
	if ip := net.ParseIP(normalized); ip != nil {
		return isPrivateAIAPIBaseIP(ip)
	}
	ips, err := net.LookupIP(normalized)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if isPrivateAIAPIBaseIP(ip) {
			return true
		}
	}
	return false
}

func isPrivateAIAPIBaseIP(ip net.IP) bool {
	return !netguard.IsPublicIP(ip)
}

func (h *Handler) AnalyzeLog(w http.ResponseWriter, r *http.Request) {
	allowLongResponseWrite(w)
	var req aiAnalyzeLogPayload
	if !decode(w, r, &req) {
		return
	}
	entry, status, code, err := h.resolveAnalyzeLogEntry(r, req)
	if err != nil {
		writeError(w, status, code, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), aiLongRequestTimeout)
	defer cancel()
	analysis, err := ai.AnalyzeLogWithLanguage(ctx, h.aiReasoningClient(), entry, req.Language)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
		return
	}
	writeData(w, analysis)
}

func (h *Handler) AnalyzeLogStream(w http.ResponseWriter, r *http.Request) {
	var req aiAnalyzeLogPayload
	if !decode(w, r, &req) {
		return
	}
	entry, status, code, err := h.resolveAnalyzeLogEntry(r, req)
	if err != nil {
		writeError(w, status, code, err.Error())
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		ctx, cancel := context.WithTimeout(r.Context(), aiLongRequestTimeout)
		defer cancel()
		analysis, err := ai.AnalyzeLogWithLanguage(ctx, h.aiReasoningClient(), entry, req.Language)
		if err != nil {
			writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
			return
		}
		w.Header().Set("X-CheeseWAF-Stream-Fallback", "json")
		writeData(w, analysis)
		return
	}
	ctx, cancel := newAIStreamContext(r.Context())
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	allowLongResponseWrite(w)
	var writeMu sync.Mutex
	writeEvent := func(event string, payload any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := writeAssistantSSE(w, flusher, event, payload); err != nil {
			cancel()
			return err
		}
		return nil
	}
	heartbeatDone := make(chan struct{})
	var heartbeatOnce sync.Once
	stopHeartbeat := func() {
		heartbeatOnce.Do(func() { close(heartbeatDone) })
	}
	defer stopHeartbeat()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if writeEvent("heartbeat", map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano)}) != nil {
					return
				}
			case <-heartbeatDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	if writeEvent("trace", ai.AssistantTraceEvent{Type: "stream_open", Message: localizedTraceMessage(req.Language, "流式分析连接已建立。", "Streaming analysis connection is open.")}) != nil {
		return
	}
	emit, stopProviderWatch := providerStreamEmitter(ctx, req.Language, "analysis", func(event ai.AssistantTraceEvent) {
		_ = writeEvent("trace", event)
	})
	defer stopProviderWatch()
	analysis, err := ai.AnalyzeLogWithLanguageStream(ctx, h.aiReasoningClient(), entry, req.Language, emit)
	stopProviderWatch()
	stopHeartbeat()
	if err != nil {
		if ctx.Err() == nil {
			_ = writeEvent("error", map[string]any{"message": err.Error(), "code": "AI_ANALYSIS_FAILED"})
		}
		return
	}
	_ = writeEvent("done", analysis)
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
	allowLongResponseWrite(w)
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
	ctx, cancel := context.WithTimeout(r.Context(), aiLongRequestTimeout)
	defer cancel()
	analyses, err := ai.AnalyzeEventsWithLanguage(ctx, h.aiReasoningClient(), entries, req.Language)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"items": analyses, "total": len(analyses)})
}

func (h *Handler) AnalyzeEventsStream(w http.ResponseWriter, r *http.Request) {
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
	flusher, ok := w.(http.Flusher)
	if !ok {
		ctx, cancel := context.WithTimeout(r.Context(), aiLongRequestTimeout)
		defer cancel()
		analyses, err := ai.AnalyzeEventsWithLanguage(ctx, h.aiReasoningClient(), entries, req.Language)
		if err != nil {
			writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
			return
		}
		w.Header().Set("X-CheeseWAF-Stream-Fallback", "json")
		writeData(w, map[string]any{"items": analyses, "total": len(analyses)})
		return
	}
	ctx, cancel := newAIStreamContext(r.Context())
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	allowLongResponseWrite(w)
	var writeMu sync.Mutex
	writeEvent := func(event string, payload any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := writeAssistantSSE(w, flusher, event, payload); err != nil {
			cancel()
			return err
		}
		return nil
	}
	heartbeatDone := make(chan struct{})
	var heartbeatOnce sync.Once
	stopHeartbeat := func() {
		heartbeatOnce.Do(func() { close(heartbeatDone) })
	}
	defer stopHeartbeat()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if writeEvent("heartbeat", map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano)}) != nil {
					return
				}
			case <-heartbeatDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	if writeEvent("trace", ai.AssistantTraceEvent{
		Type:    "stream_open",
		Mode:    "events_analysis",
		Message: localizedTraceMessage(req.Language, "批量事件流式分析连接已建立。", "Batch event analysis stream is open."),
	}) != nil {
		return
	}
	emit, stopProviderWatch := providerStreamEmitter(ctx, req.Language, "events_analysis", func(event ai.AssistantTraceEvent) {
		_ = writeEvent("trace", event)
	})
	defer stopProviderWatch()
	analyses, err := ai.AnalyzeEventsWithLanguageStream(ctx, h.aiReasoningClient(), entries, req.Language, emit, func(analysis ai.AttackAnalysis) {
		_ = writeEvent("item", analysis)
	})
	stopProviderWatch()
	stopHeartbeat()
	if err != nil {
		if ctx.Err() == nil {
			_ = writeEvent("error", map[string]any{"message": err.Error(), "code": "AI_ANALYSIS_FAILED"})
		}
		return
	}
	_ = writeEvent("done", map[string]any{"items": analyses, "total": len(analyses)})
}

func (h *Handler) RunAISelfLearning(w http.ResponseWriter, r *http.Request) {
	allowLongResponseWrite(w)
	var req aiSelfLearningRunPayload
	if r.Body != nil && r.ContentLength != 0 {
		if !decode(w, r, &req) {
			return
		}
	}
	if h.Config == nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_ERROR", "config is nil")
		return
	}
	cfg := h.Config.AI.SelfLearning
	if req.DryRun != nil {
		cfg.DryRun = *req.DryRun
	}
	// Self-learning may CreateRule when AutoApply && !DryRun. Reuse the same
	// freeze / cluster-writable guards as CreateRule; on freeze, force dry-run
	// only so the report still returns candidates without writing rules.
	ctx, cancel := context.WithTimeout(r.Context(), aiLongRequestTimeout)
	defer cancel()
	report, err := ai.RunSelfLearning(ctx, ai.SelfLearningOptions{
		Config:   cfg,
		Client:   h.aiReasoningClient(),
		Sink:     h.Sink,
		Rules:    h.Store,
		Language: req.Language,
		CanWriteRules: func() error {
			return h.selfLearningRuleWriteAllowed(r)
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_SELF_LEARNING_FAILED", err.Error())
		return
	}
	writeData(w, report)
}

// selfLearningRuleWriteAllowed mirrors rejectClusterConfigWriteIfFrozen /
// commitConfigMutation write gates without writing an HTTP error response.
func (h *Handler) selfLearningRuleWriteAllowed(r *http.Request) error {
	if h == nil {
		return fmt.Errorf("handler is nil")
	}
	h.configMutationMu.RLock()
	frozen, freezeReason := h.configWriteFrozen, h.configFreezeReason
	h.configMutationMu.RUnlock()
	if frozen {
		if strings.TrimSpace(freezeReason) == "" {
			freezeReason = "configuration state could not be restored"
		}
		return fmt.Errorf("configuration writes are frozen: %s", freezeReason)
	}
	if ok, reason := h.clusterConfigWritable(requestLanguage(r)); !ok {
		return fmt.Errorf("cluster protection mode: %s", reason)
	}
	return nil
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
	allowLongResponseWrite(w)
	var req aiAssistantPayload
	if !decode(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), aiLongRequestTimeout)
	defer cancel()
	reply, err := h.runAssistantAgent(ctx, req, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ASSISTANT_FAILED", err.Error())
		return
	}
	writeData(w, reply)
}

func (h *Handler) ListAIApprovals(w http.ResponseWriter, r *http.Request) {
	actor, canReviewAll := h.aiApprovalRecoveryAccess(r)
	approvals := h.AssistantApprovals.List()
	if !canReviewAll {
		filtered := approvals[:0]
		for _, approval := range approvals {
			if approval.RequesterSubject == actor.Subject && approval.RequesterSessionID == actor.SessionID && actor.Subject != "" {
				filtered = append(filtered, approval)
			}
		}
		approvals = filtered
	}
	writeData(w, map[string]any{
		"items": approvals,
		"total": len(approvals),
	})
}

func (h *Handler) GetAIApproval(w http.ResponseWriter, r *http.Request) {
	approval, ok := h.AssistantApprovals.Get(strings.TrimSpace(chi.URLParam(r, "id")))
	if !ok {
		writeError(w, http.StatusNotFound, "AI_APPROVAL_NOT_FOUND", "approval request not found")
		return
	}
	actor, canReviewAll := h.aiApprovalRecoveryAccess(r)
	if !canReviewAll && (actor.Subject == "" || approval.RequesterSubject != actor.Subject || approval.RequesterSessionID != actor.SessionID) {
		writeError(w, http.StatusForbidden, "AI_APPROVAL_FORBIDDEN", "approval belongs to another requester session")
		return
	}
	writeData(w, approval)
}

func (h *Handler) aiApprovalRecoveryAccess(r *http.Request) (ai.ApprovalActor, bool) {
	actor := h.aiApprovalActor(r)
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	permissions := config.Default().APISec.Permissions
	if h != nil && h.Config != nil && len(h.Config.APISec.Permissions) > 0 {
		permissions = h.Config.APISec.Permissions
	}
	return actor, callerHasPermission(claims, permissions, "approve:ai")
}

func (h *Handler) AIAssistantStream(w http.ResponseWriter, r *http.Request) {
	var req aiAssistantPayload
	if !decode(w, r, &req) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		ctx, cancel := newAIStreamContext(r.Context())
		defer cancel()
		reply, err := h.runAssistantAgent(ctx, req, nil)
		if err != nil {
			writeError(w, http.StatusBadGateway, "AI_ASSISTANT_FAILED", err.Error())
			return
		}
		w.Header().Set("X-CheeseWAF-Stream-Fallback", "json")
		writeData(w, reply)
		return
	}
	ctx, cancel := newAIStreamContext(r.Context())
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	allowLongResponseWrite(w)
	var writeMu sync.Mutex
	writeEvent := func(event string, payload any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := writeAssistantSSE(w, flusher, event, payload); err != nil {
			cancel()
			return err
		}
		return nil
	}
	heartbeatDone := make(chan struct{})
	var heartbeatOnce sync.Once
	stopHeartbeat := func() {
		heartbeatOnce.Do(func() {
			close(heartbeatDone)
		})
	}
	defer stopHeartbeat()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := writeEvent("heartbeat", map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
					return
				}
			case <-heartbeatDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	if err := writeEvent("trace", ai.AssistantTraceEvent{Type: "stream_open", Message: localizedTraceMessage(req.Language, "流式连接已建立。", "Streaming connection is open.")}); err != nil {
		return
	}
	emit := func(event ai.AssistantTraceEvent) {
		_ = writeEvent("trace", event)
	}
	reply, err := h.runAssistantAgent(ctx, req, emit)
	stopHeartbeat()
	if err != nil {
		if ctx.Err() == nil {
			_ = writeEvent("error", map[string]any{"message": err.Error()})
		}
		return
	}
	_ = writeEvent("done", reply)
}

func newAIStreamContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, aiLongRequestTimeout)
}

func allowLongResponseWrite(w http.ResponseWriter) {
	if controller := http.NewResponseController(w); controller != nil {
		_ = controller.SetWriteDeadline(time.Time{})
	}
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
	var traceMu sync.Mutex
	record := func(event ai.AssistantTraceEvent) {
		traceMu.Lock()
		defer traceMu.Unlock()
		event.At = time.Now().UTC().Format(time.RFC3339Nano)
		trace = append(trace, event)
		if emit != nil {
			emit(event)
		}
	}
	record(ai.AssistantTraceEvent{Type: "safety_boundary", Message: localizedTraceMessage(req.Language, "安全边界已启用。", "Safety boundary is enabled.")})
	client := h.aiClientForAssistant(req.DeepThink)
	var reply *ai.AssistantReply
	if client == nil {
		record(ai.AssistantTraceEvent{Type: "local_router", Message: localizedTraceMessage(req.Language, "AI 未配置，使用本地分析。", "AI is not configured; using local analysis.")})
		entries := h.queryLogsFromContext(ctx, storage.LogFilter{Limit: limit})
		runtime := map[string]any{"snapshot": h.monitorSnapshotFromContext(ctx)}
		var err error
		reply, err = ai.AnswerAssistantWithLanguage(ctx, nil, req.Message, entries, runtime, req.Language)
		if err != nil {
			return nil, err
		}
		reply.ToolExecutions = append(reply.ToolExecutions, h.executeAssistantToolRequests(ctx, intentsToToolRequests(h.assistantToolIntents(req.Message)), record)...)
		reply.Trace = trace
		return reply, nil
	}
	registry := h.aiAssistantRegistry()
	toolDefinitions := registry.ListForLLM()
	record(ai.AssistantTraceEvent{Type: "tool_gateway_ready", Message: localizedTraceMessage(req.Language, fmt.Sprintf("可用工具：%d 个。", len(toolDefinitions)), fmt.Sprintf("Available tools: %d.", len(toolDefinitions)))})
	record(ai.AssistantTraceEvent{Type: "planning_start", Message: localizedTraceMessage(req.Language, "正在判断是否需要读取运行数据。", "Checking whether runtime data is needed.")})
	var plan *ai.AssistantPlan
	var err error
	if emit != nil {
		planEmit, stopPlanWatch := providerStreamEmitter(ctx, req.Language, "planning", record)
		plan, err = ai.PlanAssistantToolCallsStream(ctx, client, req.Message, req.Language, toolDefinitions, planEmit)
		stopPlanWatch()
	} else {
		plan, err = ai.PlanAssistantToolCalls(ctx, client, req.Message, req.Language, toolDefinitions)
	}
	if err != nil {
		requests := intentsToToolRequests(h.assistantToolIntents(req.Message))
		if len(requests) > 0 {
			record(ai.AssistantTraceEvent{Type: "planning_error", Message: localizedTraceMessage(req.Language, "运行数据读取规划失败，改用本地分析。", "Runtime-data planning failed; using local analysis."), Error: err.Error()})
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
	if strings.TrimSpace(plan.ReasoningSummary) != "" {
		record(ai.AssistantTraceEvent{Type: "reasoning_summary", Message: plan.ReasoningSummary, Provider: plan.Provider, Model: plan.Model})
	}
	requests := plan.ToolRequests
	if len(requests) == 0 {
		requests = intentsToToolRequests(h.assistantToolIntents(req.Message))
		if len(requests) > 0 {
			record(ai.AssistantTraceEvent{Type: "local_intent_tools", Message: localizedTraceMessage(req.Language, "已根据问题补充读取运行数据。", "Runtime-data reads were added from the question.")})
		}
	}
	if len(requests) == 0 {
		reply = &ai.AssistantReply{
			Answer:           plan.Answer,
			ReasoningSummary: plan.ReasoningSummary,
			AIUsed:           true,
			Provider:         plan.Provider,
			Model:            plan.Model,
			InputTokens:      plan.InputTokens,
			OutputTokens:     plan.OutputTokens,
			TotalTokens:      plan.TotalTokens,
		}
		reply.Trace = trace
		return reply, nil
	}
	calls := h.executeAssistantToolRequests(ctx, requests, record)
	record(ai.AssistantTraceEvent{Type: "final_start", Message: localizedTraceMessage(req.Language, "运行数据已返回，正在生成回答。", "Runtime data has returned; generating the answer.")})
	if emit != nil {
		finalEmit, stopFinalWatch := providerStreamEmitter(ctx, req.Language, "final", record)
		reply, err = ai.AnswerAssistantWithToolResultsStream(ctx, client, req.Message, req.Language, toolDefinitions, calls, finalEmit)
		stopFinalWatch()
	} else {
		reply, err = ai.AnswerAssistantWithToolResults(ctx, client, req.Message, req.Language, toolDefinitions, calls)
	}
	if err != nil {
		providerErr := err
		record(ai.AssistantTraceEvent{Type: "final_error", Message: localizedTraceMessage(req.Language, "AI 总结失败，返回本地摘要。", "AI summarization failed; returning a local summary."), Error: providerErr.Error()})
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
	if strings.TrimSpace(reply.ReasoningSummary) == "" {
		reply.ReasoningSummary = plan.ReasoningSummary
	}
	record(ai.AssistantTraceEvent{
		Type:         "final_done",
		Message:      localizedTraceMessage(req.Language, "回答已生成。", "Answer generated."),
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
	if len(intents) == 0 && containsAny(normalized,
		"knowledge", "docs", "how", "why", "rule", "policy", "config", "certificate", "acme", "false positive", "false negative", "cache", "compression",
	) {
		intents = append(intents, assistantToolIntent{Name: "knowledge_base", Args: map[string]any{"query": normalized, "limit": 5}})
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

func appendProviderFailure(answer, language string, err error) string {
	if err == nil {
		return answer
	}
	message := "AI service provider request failed. Showing deterministic local analysis instead. Error: " + err.Error()
	if strings.Contains(strings.ToLower(language), "zh") {
		message = "AI 服务商请求失败，已改为显示本地确定性分析。错误：" + err.Error()
	}
	if strings.TrimSpace(answer) == "" {
		return message
	}
	return strings.TrimSpace(answer) + "\n\n" + message
}

func providerStreamEmitter(ctx context.Context, language, phase string, record func(ai.AssistantTraceEvent)) (ai.StreamEmitter, func()) {
	first := make(chan struct{})
	done := make(chan struct{})
	var firstOnce sync.Once
	var stopOnce sync.Once
	markFirst := func() {
		firstOnce.Do(func() {
			close(first)
		})
	}
	go func() {
		slowAfter := providerFirstEventSlowAfter
		if slowAfter <= 0 {
			slowAfter = 10 * time.Second
		}
		progressInterval := providerWaitingProgressInterval
		if progressInterval <= 0 {
			progressInterval = slowAfter
		}
		timer := time.NewTimer(slowAfter)
		defer timer.Stop()
		select {
		case <-first:
			return
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-timer.C:
			record(ai.AssistantTraceEvent{
				Type:    "provider_first_event_slow",
				Mode:    phase,
				Message: localizedProviderSlowMessage(language, phase),
			})
		}
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-first:
				return
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				record(ai.AssistantTraceEvent{
					Type:    "provider_waiting_progress",
					Mode:    phase,
					Message: localizedProviderWaitingMessage(language, phase),
				})
			}
		}
	}()
	emit := func(event ai.AssistantTraceEvent) {
		if isProviderFirstEvent(event.Type) {
			markFirst()
		}
		event.Message = localizedProviderTraceMessage(language, event)
		record(event)
	}
	stop := func() {
		stopOnce.Do(func() {
			close(done)
		})
	}
	return emit, stop
}

func isProviderFirstEvent(kind string) bool {
	switch kind {
	case "provider_response_start", "reasoning_delta", "content_delta", "tool_call_delta":
		return true
	default:
		return false
	}
}

func localizedProviderTraceMessage(language string, event ai.AssistantTraceEvent) string {
	switch event.Type {
	case "provider_response_start":
		return localizedTraceMessage(language, "AI 服务商已开始返回响应。", "AI service provider started streaming a response.")
	case "provider_first_event_slow":
		if strings.TrimSpace(event.Message) != "" {
			return event.Message
		}
		return localizedProviderSlowMessage(language, event.Mode)
	case "provider_waiting_progress":
		if strings.TrimSpace(event.Message) != "" {
			return event.Message
		}
		return localizedProviderWaitingMessage(language, event.Mode)
	default:
		return event.Message
	}
}

func localizedProviderSlowMessage(language, phase string) string {
	if strings.Contains(strings.ToLower(language), "en") {
		return "AI service provider has not started streaming within 10s during " + nonEmpty(phase, "this step") + "; keeping the request open."
	}
	switch phase {
	case "planning":
		return "AI 服务商在 10 秒内还没有开始规划返回；请求会继续保持，不会把最终回答误判为超时。"
	case "final":
		return "AI 服务商在 10 秒内还没有开始生成最终回答；请求会继续保持，不会把完整回复耗时误判为首包超时。"
	case "analysis":
		return "AI 服务商在 10 秒内还没有开始返回事件分析；请求会继续保持，不会把完整分析耗时误判为首包超时。"
	default:
		return "AI 服务商在 10 秒内还没有开始返回响应；请求会继续保持。"
	}
}

func localizedProviderWaitingMessage(language, phase string) string {
	if strings.Contains(strings.ToLower(language), "en") {
		return "AI service provider is still processing during " + nonEmpty(phase, "this step") + "; keeping the stream alive."
	}
	switch phase {
	case "planning":
		return "AI 服务商仍在规划工具调用，连接保持中。"
	case "final":
		return "AI 服务商仍在生成最终回答，连接保持中。"
	case "analysis":
		return "AI 服务商仍在分析事件，连接保持中。"
	default:
		return "AI 服务商仍在处理，连接保持中。"
	}
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

func writeAssistantSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw, _ = json.Marshal(map[string]any{"message": err.Error()})
		event = "error"
	}
	frame := fmt.Sprintf("event: %s\ndata: %s\n\n", event, raw)
	if _, err := io.WriteString(w, frame); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func (h *Handler) aiClient() *ai.Client {
	return h.aiAssistantClient()
}

func (h *Handler) aiAssistantClient() *ai.Client {
	if h == nil || h.Config == nil {
		return nil
	}
	cfg := h.Config.AI.AssistantRuntimeConfig()
	if cfg.Enabled && cfg.APIKey != "" {
		return ai.NewClient(cfg, nil)
	}
	return nil
}

func (h *Handler) aiReasoningClient() *ai.Client {
	if h == nil || h.Config == nil {
		return nil
	}
	cfg := h.Config.AI.ReasoningRuntimeConfig()
	if cfg.Enabled && cfg.APIKey != "" {
		return ai.NewClient(cfg, nil)
	}
	return nil
}

func (h *Handler) aiClientForAssistant(deepThink bool) *ai.Client {
	if deepThink {
		if client := h.aiReasoningClient(); client != nil {
			return client
		}
	}
	return h.aiAssistantClient()
}

func (h *Handler) aiRuntimeConfig(target string) config.AIConfig {
	if h == nil || h.Config == nil {
		cfg := config.Default().AI
		cfg.Enabled = false
		return cfg
	}
	switch normalizeAITarget(target) {
	case "reasoning":
		return h.Config.AI.ReasoningRuntimeConfig()
	default:
		return h.Config.AI.AssistantRuntimeConfig()
	}
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
	assistant := cfg.AssistantRuntimeConfig()
	reasoning := cfg.ReasoningRuntimeConfig()
	return aiConfigPayload{
		Enabled:             cfg.Enabled,
		Provider:            assistant.Provider,
		APIBase:             assistant.APIBase,
		APIKeySet:           assistant.APIKey != "",
		Model:               assistant.Model,
		Async:               cfg.Async,
		AllowPrivateAPIBase: assistant.AllowPrivateAPIBase,
		Assistant:           aiModelConfigView(assistant.RuntimeModelConfig()),
		Reasoning:           aiModelConfigView(reasoning.RuntimeModelConfig()),
		SelfLearning:        aiSelfLearningView(cfg.SelfLearning),
		Knowledge:           &cfg.Knowledge,
	}
}

func aiSelfLearningView(cfg config.AISelfLearningConfig) *aiSelfLearningConfigView {
	interval := cfg.Interval
	if interval == 0 {
		interval = 24 * time.Hour
	}
	return &aiSelfLearningConfigView{
		Enabled:        cfg.Enabled,
		AutoApply:      cfg.AutoApply,
		DryRun:         cfg.DryRun,
		Interval:       durationForDisplay(interval),
		At:             cfg.At,
		MinConfidence:  cfg.MinConfidence,
		MinEvents:      cfg.MinEvents,
		MaxEvents:      cfg.MaxEvents,
		MaxRulesPerRun: cfg.MaxRulesPerRun,
		Action:         cfg.Action,
	}
}

func parseAISelfLearningConfig(value any, fallback config.AISelfLearningConfig) (config.AISelfLearningConfig, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return fallback, fmt.Errorf("encode self_learning config: %w", err)
	}
	var loose map[string]any
	if err := json.Unmarshal(raw, &loose); err != nil {
		return fallback, fmt.Errorf("decode self_learning config: %w", err)
	}
	next := fallback
	if value, ok := loose["enabled"].(bool); ok {
		next.Enabled = value
	}
	if value, ok := loose["auto_apply"].(bool); ok {
		next.AutoApply = value
	}
	if value, ok := loose["dry_run"].(bool); ok {
		next.DryRun = value
	}
	if value, ok := loose["at"].(string); ok {
		next.At = value
	}
	if value, ok := loose["action"].(string); ok {
		next.Action = value
	}
	if value, ok := readLooseFloat(loose["min_confidence"]); ok {
		next.MinConfidence = value
	}
	if value, ok := readLooseInt(loose["min_events"]); ok {
		next.MinEvents = value
	}
	if value, ok := readLooseInt(loose["max_events"]); ok {
		next.MaxEvents = value
	}
	if value, ok := readLooseInt(loose["max_rules_per_run"]); ok {
		next.MaxRulesPerRun = value
	}
	if duration, ok, err := readLooseDuration(loose["interval"]); err != nil {
		return fallback, err
	} else if ok {
		next.Interval = duration
	}
	return next, nil
}

func readLooseDuration(value any) (time.Duration, bool, error) {
	switch typed := value.(type) {
	case nil:
		return 0, false, nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false, nil
		}
		if strings.HasSuffix(trimmed, "d") {
			days, err := strconv.ParseFloat(strings.TrimSuffix(trimmed, "d"), 64)
			if err != nil {
				return 0, false, fmt.Errorf("self_learning.interval must be a duration such as 24h: %w", err)
			}
			return time.Duration(days * float64(24*time.Hour)), true, nil
		}
		parsed, err := time.ParseDuration(trimmed)
		if err != nil {
			return 0, false, fmt.Errorf("self_learning.interval must be a duration such as 24h: %w", err)
		}
		return parsed, true, nil
	case float64:
		if typed <= 0 {
			return 0, false, nil
		}
		return time.Duration(typed), true, nil
	default:
		return 0, false, fmt.Errorf("self_learning.interval must be a duration string or nanoseconds")
	}
}

func readLooseFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func readLooseInt(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func durationForDisplay(value time.Duration) string {
	if value%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(value/time.Hour))
	}
	if value%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(value/time.Minute))
	}
	if value%time.Second == 0 {
		return fmt.Sprintf("%ds", int(value/time.Second))
	}
	return value.String()
}

func aiModelConfigView(cfg config.AIModelConfig) *aiModelConfigPayload {
	provider := cfg.Provider
	if provider == "" {
		provider = "openai"
	}
	return &aiModelConfigPayload{
		Provider:            provider,
		APIBase:             cfg.APIBase,
		APIKeySet:           cfg.APIKey != "",
		Model:               cfg.Model,
		AllowPrivateAPIBase: cfg.AllowPrivateAPIBase,
	}
}

func mergeAIModelPayload(current config.AIModelConfig, req aiModelConfigPayload) config.AIModelConfig {
	next := current
	if strings.TrimSpace(req.Provider) != "" {
		next.Provider = strings.TrimSpace(req.Provider)
	}
	if strings.TrimSpace(req.APIBase) != "" {
		next.APIBase = strings.TrimSpace(req.APIBase)
	}
	if strings.TrimSpace(req.APIKey) != "" {
		next.APIKey = req.APIKey
	}
	if strings.TrimSpace(req.Model) != "" {
		next.Model = strings.TrimSpace(req.Model)
	}
	next.AllowPrivateAPIBase = req.AllowPrivateAPIBase
	if strings.TrimSpace(next.APIKeyHeader) == "" {
		next.APIKeyHeader = "authorization"
	}
	return next
}

func aiModelPayloadFromConfig(model config.AIModelConfig) aiModelConfigPayload {
	return aiModelConfigPayload{
		Provider:            model.Provider,
		APIBase:             model.APIBase,
		APIKey:              model.APIKey,
		Model:               model.Model,
		AllowPrivateAPIBase: model.AllowPrivateAPIBase,
	}
}

func legacyAIModelPayload(cfg config.AIConfig) aiModelConfigPayload {
	return aiModelConfigPayload{
		Provider:            cfg.Provider,
		APIBase:             cfg.APIBase,
		APIKey:              cfg.APIKey,
		Model:               cfg.Model,
		AllowPrivateAPIBase: cfg.AllowPrivateAPIBase,
	}
}

func validateAIConfigForSave(cfg config.AIConfig) error {
	if cfg.Enabled {
		if err := validateRuntimeAIConfig("assistant", cfg.AssistantRuntimeConfig()); err != nil {
			return err
		}
		if err := validateRuntimeAIConfig("reasoning", cfg.ReasoningRuntimeConfig()); err != nil {
			return err
		}
	}
	if cfg.SelfLearning.MinConfidence < 0 || cfg.SelfLearning.MinConfidence > 1 {
		return fmt.Errorf("self_learning.min_confidence must be between 0 and 1")
	}
	if cfg.SelfLearning.Interval != 0 && cfg.SelfLearning.Interval < time.Hour {
		return fmt.Errorf("self_learning.interval must be at least 1h")
	}
	return nil
}

func validateRuntimeAIConfig(target string, cfg config.AIConfig) error {
	if strings.TrimSpace(cfg.APIBase) == "" {
		return fmt.Errorf("%s api base is required", target)
	}
	if err := validateAIAPIBase(cfg.APIBase, cfg.AllowPrivateAPIBase); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return fmt.Errorf("%s model is required", target)
	}
	return nil
}

func validateAITestConfig(cfg config.AIConfig) error {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("ai api key is required")
	}
	if strings.TrimSpace(cfg.APIBase) == "" {
		return fmt.Errorf("ai api base is required")
	}
	if err := validateAIAPIBase(cfg.APIBase, cfg.AllowPrivateAPIBase); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return fmt.Errorf("ai model is required")
	}
	return nil
}

func aiTestValidationErrorCode(err error) string {
	if err == nil {
		return "AI_CONFIG_INVALID"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "api key"):
		return "AI_KEY_REQUIRED"
	case strings.Contains(message, "api base is required"):
		return "AI_API_BASE_REQUIRED"
	case isAIAPIBaseValidationError(err):
		return "AI_API_BASE_INVALID"
	case strings.Contains(message, "model"):
		return "AI_MODEL_REQUIRED"
	default:
		return "AI_CONFIG_INVALID"
	}
}

func isAIAPIBaseValidationError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "api base") || strings.Contains(message, "api_base")
}

func normalizeAITarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "reasoning", "reason", "deep_think", "deep-think", "推理":
		return "reasoning"
	default:
		return "assistant"
	}
}
