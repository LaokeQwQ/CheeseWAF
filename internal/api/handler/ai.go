package handler

import (
	"encoding/json"
	"net/http"
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
}

type aiAssistantPayload struct {
	Message string `json:"message"`
	Limit   int    `json:"limit"`
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
	var entry storage.LogEntry
	if !decode(w, r, &entry) {
		return
	}
	analysis, err := ai.AnalyzeLog(r.Context(), h.aiClient(), entry)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
		return
	}
	writeData(w, analysis)
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
	analyses, err := ai.AnalyzeEvents(r.Context(), h.aiClient(), entries)
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
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "message is required")
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	entries := h.queryLogs(r, storage.LogFilter{Limit: limit})
	snapshot := h.monitorSnapshot(r)
	snapshotJSON, _ := json.Marshal(snapshot)
	var runtime map[string]any
	_ = json.Unmarshal(snapshotJSON, &runtime)
	reply, err := ai.AnswerAssistant(r.Context(), h.aiClient(), req.Message, entries, runtime)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ASSISTANT_FAILED", err.Error())
		return
	}
	writeData(w, reply)
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
