package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

const maxNotificationsPageSize = 100

type notificationPatchRequest struct {
	Read   *bool `json:"read"`
	Pinned *bool `json:"pinned"`
}

func (h *Handler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	userID, ok := notificationUserID(w, r)
	if !ok {
		return
	}
	page, ok := notificationQueryInt(w, r, "page", 1, 1_000_000)
	if !ok {
		return
	}
	limit, ok := notificationQueryInt(w, r, "limit", 20, maxNotificationsPageSize)
	if !ok {
		return
	}
	filter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("filter")))
	if filter == "" {
		filter = "all"
	}
	items, total, filteredTotal, unread, err := h.Store.ListNotifications(r.Context(), userID, storage.NotificationFilter{
		State: filter, Offset: (page - 1) * limit, Limit: limit,
	})
	if err != nil {
		if strings.Contains(err.Error(), "invalid notification filter") {
			writeError(w, http.StatusBadRequest, "NOTIFICATION_FILTER_INVALID", "filter must be all, unread, read, or pinned")
			return
		}
		writeError(w, http.StatusInternalServerError, "NOTIFICATION_LIST_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{
		"items": items, "total": total, "filtered_total": filteredTotal,
		"page": page, "limit": limit, "unread": unread,
	})
}

func (h *Handler) UpdateNotification(w http.ResponseWriter, r *http.Request) {
	userID, ok := notificationUserID(w, r)
	if !ok {
		return
	}
	var req notificationPatchRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Read == nil && req.Pinned == nil {
		writeError(w, http.StatusBadRequest, "NOTIFICATION_PATCH_EMPTY", "read or pinned is required")
		return
	}
	item, err := h.Store.UpdateNotification(r.Context(), userID, chi.URLParam(r, "id"), storage.NotificationPatch{Read: req.Read, Pinned: req.Pinned})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "NOTIFICATION_UPDATE_ERROR", err.Error())
		return
	}
	if item == nil {
		writeError(w, http.StatusNotFound, "NOTIFICATION_NOT_FOUND", "notification not found")
		return
	}
	writeData(w, item)
}

func (h *Handler) MarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	userID, ok := notificationUserID(w, r)
	if !ok {
		return
	}
	updated, err := h.Store.MarkAllNotificationsRead(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "NOTIFICATION_READ_ALL_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"updated": updated})
}

func (h *Handler) ClearNotifications(w http.ResponseWriter, r *http.Request) {
	userID, ok := notificationUserID(w, r)
	if !ok {
		return
	}
	deleted, err := h.Store.ClearNotifications(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "NOTIFICATION_CLEAR_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"deleted": deleted})
}

func notificationUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, _ := r.Context().Value(middleware.UserContextKey).(*middleware.Claims)
	if claims == nil || strings.TrimSpace(claims.Subject) == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return "", false
	}
	return claims.Subject, true
}

func notificationQueryInt(w http.ResponseWriter, r *http.Request, name string, fallback, maximum int) (int, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback, true
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 || value > maximum {
		writeError(w, http.StatusBadRequest, "PAGINATION_INVALID", name+" is outside the allowed range")
		return 0, false
	}
	return value, true
}
