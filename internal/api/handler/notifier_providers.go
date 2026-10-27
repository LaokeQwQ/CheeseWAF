package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	monitornotify "github.com/LaokeQwQ/CheeseWAF/internal/monitor/notifier"
)

type notifierProviderView struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type"`
	Enabled    bool   `json:"enabled"`
	Configured bool   `json:"configured"`
}

type notifierTestRequest struct {
	ID string `json:"id"`
}

// ListNotifierProviders returns the configured native providers without
// endpoints, tokens, headers, or recipient secrets.
func (h *Handler) ListNotifierProviders(w http.ResponseWriter, _ *http.Request) {
	cfg := h.currentConfig()
	providers := make([]notifierProviderView, 0)
	if cfg != nil {
		for _, item := range cfg.Monitor.Notifiers {
			providers = append(providers, notifierProviderView{
				ID: item.ID, Name: item.Name, Type: item.Type,
				Enabled: item.Enabled, Configured: item.Enabled && strings.TrimSpace(item.Endpoint) != "",
			})
		}
	}
	writeData(w, map[string]any{"providers": providers, "count": len(providers)})
}

// TestNotifierProvider delivers a synthetic alert through one configured
// provider. It uses the same native implementation and SSRF policy as real
// alerts, so a successful test exercises endpoint, credentials, and payload.
func (h *Handler) TestNotifierProvider(w http.ResponseWriter, r *http.Request) {
	var request notifierTestRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid notifier test request")
		return
	}
	id := strings.TrimSpace(request.ID)
	if id == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_provider", "provider id is required")
		return
	}
	cfg := h.currentConfig()
	if cfg == nil {
		writeError(w, http.StatusServiceUnavailable, "config_unavailable", "configuration is not available")
		return
	}
	for _, item := range cfg.Monitor.Notifiers {
		if item.ID != id {
			continue
		}
		if !item.Enabled {
			writeError(w, http.StatusConflict, "provider_disabled", "provider is disabled")
			return
		}
		// Use the shared registry so a pack-provided type resolves here too; a
		// fresh registry would reject it and make "Send test" fail with 422 for
		// a provider that works in production.
		registry := h.NotifierRegistry
		if registry == nil {
			registry = monitornotify.NewRegistry()
		}
		provider, err := registry.New(item, nil)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "provider_invalid", "provider configuration is invalid")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		alert := monitor.Alert{
			RuleID: "test.notification", Name: "CheeseWAF test notification",
			Metric: "test", Severity: "info", Message: "Test notification from CheeseWAF.",
			StartsAt: time.Now().UTC(),
		}
		if err := provider.Notify(ctx, alert); err != nil {
			writeError(w, http.StatusBadGateway, "delivery_failed", err.Error())
			return
		}
		writeData(w, map[string]any{"id": item.ID, "delivered": true})
		return
	}
	writeError(w, http.StatusNotFound, "provider_not_found", "provider is not configured")
}
