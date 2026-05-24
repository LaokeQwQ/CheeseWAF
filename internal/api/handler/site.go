package handler

import (
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) ListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := h.Store.ListSites(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, sites)
}

func (h *Handler) CreateSite(w http.ResponseWriter, r *http.Request) {
	var site storage.Site
	if !decode(w, r, &site) {
		return
	}
	if err := h.Store.CreateSite(r.Context(), &site); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, site)
}

func (h *Handler) UpdateSite(w http.ResponseWriter, r *http.Request) {
	var site storage.Site
	if !decode(w, r, &site) {
		return
	}
	site.ID = chi.URLParam(r, "id")
	if err := h.Store.UpdateSite(r.Context(), &site); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, site)
}

func (h *Handler) DeleteSite(w http.ResponseWriter, r *http.Request) {
	if err := h.Store.DeleteSite(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusInternalServerError, "STORE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]bool{"deleted": true})
}
