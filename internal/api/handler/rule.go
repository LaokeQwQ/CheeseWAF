package handler

import (
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.Store.ListRules(r.Context(), r.URL.Query().Get("site_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, rules)
}

func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var rule storage.Rule
	if !decode(w, r, &rule) {
		return
	}
	if !h.validateRule(w, r, &rule) {
		return
	}
	if err := h.Store.CreateRule(r.Context(), &rule); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, rule)
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var rule storage.Rule
	if !decode(w, r, &rule) {
		return
	}
	rule.ID = chi.URLParam(r, "id")
	if !h.validateRule(w, r, &rule) {
		return
	}
	if err := h.Store.UpdateRule(r.Context(), &rule); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, rule)
}

func (h *Handler) validateRule(w http.ResponseWriter, r *http.Request, rule *storage.Rule) bool {
	if rule == nil {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "rule is required")
		return false
	}
	rule.SiteID = strings.TrimSpace(rule.SiteID)
	rule.Pattern = strings.TrimSpace(rule.Pattern)
	rule.Location = strings.ToLower(strings.TrimSpace(rule.Location))
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	rule.Severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	if rule.SiteID == "" {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "site_id is required")
		return false
	}
	site, err := h.Store.GetSite(r.Context(), rule.SiteID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return false
	}
	if site == nil {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", "site_id does not reference an existing site")
		return false
	}
	if err := config.ValidateCustomRule(config.CustomRuleConfig{
		ID: rule.ID, Name: rule.Name, Pattern: rule.Pattern, Location: rule.Location,
		Action: rule.Action, Severity: rule.Severity, Enabled: rule.Enabled, Priority: rule.Priority,
	}); err != nil {
		writeError(w, http.StatusBadRequest, "RULE_INVALID", err.Error())
		return false
	}
	return true
}

func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	if err := h.Store.DeleteRule(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]bool{"deleted": true})
}
