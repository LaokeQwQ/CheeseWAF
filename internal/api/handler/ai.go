package handler

import (
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type aiConfigPayload struct {
	Enabled   bool   `json:"enabled"`
	APIBase   string `json:"api_base"`
	APIKey    string `json:"api_key"`
	APIKeySet bool   `json:"api_key_set"`
	Model     string `json:"model"`
	Async     bool   `json:"async"`
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
		Enabled: req.Enabled,
		APIBase: req.APIBase,
		APIKey:  req.APIKey,
		Model:   req.Model,
		Async:   req.Async,
	}
	if next.APIKey == "" {
		next.APIKey = h.Config.AI.APIKey
	}
	h.Config.AI = next
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
	var client *ai.Client
	if h.Config.AI.Enabled && h.Config.AI.APIKey != "" {
		client = ai.NewClient(h.Config.AI, nil)
	}
	analysis, err := ai.AnalyzeLog(r.Context(), client, entry)
	if err != nil {
		writeError(w, http.StatusBadGateway, "AI_ANALYSIS_FAILED", err.Error())
		return
	}
	writeData(w, analysis)
}

func aiConfigView(cfg config.AIConfig) aiConfigPayload {
	return aiConfigPayload{
		Enabled:   cfg.Enabled,
		APIBase:   cfg.APIBase,
		APIKeySet: cfg.APIKey != "",
		Model:     cfg.Model,
		Async:     cfg.Async,
	}
}
