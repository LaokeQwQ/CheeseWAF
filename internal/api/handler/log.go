package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func (h *Handler) ListLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}
	startTime, ok := parseLogTimeQuery(w, r, "start")
	if !ok {
		return
	}
	endTime, ok := parseLogTimeQuery(w, r, "end")
	if !ok {
		return
	}
	filter := storage.LogFilter{
		SiteID:    r.URL.Query().Get("site_id"),
		ClientIP:  r.URL.Query().Get("client_ip"),
		Category:  r.URL.Query().Get("category"),
		Action:    r.URL.Query().Get("action"),
		TraceID:   r.URL.Query().Get("trace_id"),
		StartTime: startTime,
		EndTime:   endTime,
		Limit:     limit,
	}
	if h.Sink == nil {
		writeData(w, map[string]any{"items": []storage.LogEntry{}, "total": 0})
		return
	}
	entries, total, err := h.Sink.Query(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LOG_QUERY_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"items": entries, "total": total})
}

func parseLogTimeQuery(w http.ResponseWriter, r *http.Request, name string) (time.Time, bool) {
	raw := r.URL.Query().Get(name)
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
