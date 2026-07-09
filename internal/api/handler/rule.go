package handler

import (
	"net/http"

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
	if err := h.Store.UpdateRule(r.Context(), &rule); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, rule)
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
