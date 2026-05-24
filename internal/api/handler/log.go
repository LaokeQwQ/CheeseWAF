package handler

import (
	"net/http"
	"strconv"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func (h *Handler) ListLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}
	filter := storage.LogFilter{
		SiteID:   r.URL.Query().Get("site_id"),
		ClientIP: r.URL.Query().Get("client_ip"),
		Category: r.URL.Query().Get("category"),
		Action:   r.URL.Query().Get("action"),
		TraceID:  r.URL.Query().Get("trace_id"),
		Limit:    limit,
	}
	if h.Sink == nil {
		writeData(w, []storage.LogEntry{})
		return
	}
	entries, total, err := h.Sink.Query(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LOG_QUERY_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"items": entries, "total": total})
}
