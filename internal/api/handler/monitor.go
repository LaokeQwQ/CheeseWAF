package handler

import (
	"bytes"
	"net/http"
	"path/filepath"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/apisec"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type validateRequestPayload struct {
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Headers       map[string]string `json:"headers"`
	ContentLength int64             `json:"content_length"`
}

func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	snapshot := h.monitorSnapshot(r)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(monitor.RenderPrometheus(snapshot))
}

func (h *Handler) MonitorSummary(w http.ResponseWriter, r *http.Request) {
	snapshot := h.monitorSnapshot(r)
	alerter := monitor.NewAlerter(h.Config.Monitor.Alerts)
	writeData(w, map[string]any{
		"snapshot": snapshot,
		"metrics":  monitor.Values(snapshot),
		"alerts":   alerter.Evaluate(snapshot),
		"config":   h.Config.Monitor,
	})
}

func (h *Handler) APIEndpoints(w http.ResponseWriter, r *http.Request) {
	logs := h.recentLogs(r, 1000)
	writeData(w, map[string]any{
		"endpoints": apisec.Discover(logs, h.Config.APISec.Discovery, time.Now().UTC()),
		"config":    h.Config.APISec,
	})
}

func (h *Handler) ValidateAPIRequest(w http.ResponseWriter, r *http.Request) {
	var req validateRequestPayload
	if !decode(w, r, &req) {
		return
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	url := req.Path
	if req.Query != "" {
		url += "?" + req.Query
	}
	sample, err := http.NewRequest(req.Method, url, bytes.NewReader(nil))
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	sample.ContentLength = req.ContentLength
	for key, value := range req.Headers {
		sample.Header.Set(key, value)
	}
	validator, err := apisec.NewValidator(h.Config.APISec.Validation)
	if err != nil {
		writeError(w, http.StatusBadRequest, "API_SCHEMA_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"findings": validator.Validate(sample)})
}

func (h *Handler) monitorSnapshot(r *http.Request) monitor.Snapshot {
	logs, total, ok := h.queryLogsWithTotal(r, storage.LogFilter{Limit: 1000})
	snapshot := monitor.Collect(h.StartedAt, len(h.Config.Sites), logs, map[string]int64{
		"data": dirSize(h.Config.Setup.DataDir),
		"logs": dirSize(logDir(h.Config.Logging.Output.File.Path)),
	})
	if ok {
		snapshot.Requests = intFromTotal(total)
		if blocked, ok := h.logCount(r, storage.LogFilter{Action: "block"}); ok {
			snapshot.Blocked = intFromTotal(blocked)
		}
		if challenges, ok := h.logCount(r, storage.LogFilter{Action: "challenge"}); ok {
			snapshot.Challenges = intFromTotal(challenges)
		}
	}
	return snapshot
}

func (h *Handler) recentLogs(r *http.Request, limit int) []storage.LogEntry {
	logs, _, _ := h.queryLogsWithTotal(r, storage.LogFilter{Limit: limit})
	return logs
}

func (h *Handler) logCount(r *http.Request, filter storage.LogFilter) (int64, bool) {
	filter.Limit = 1
	_, total, ok := h.queryLogsWithTotal(r, filter)
	return total, ok
}

func (h *Handler) queryLogsWithTotal(r *http.Request, filter storage.LogFilter) ([]storage.LogEntry, int64, bool) {
	if h.Sink == nil {
		return nil, 0, false
	}
	logs, total, err := h.Sink.Query(r.Context(), filter)
	if err != nil {
		return nil, 0, false
	}
	return logs, total, true
}

func intFromTotal(total int64) int {
	if total <= 0 {
		return 0
	}
	maxInt := int64(^uint(0) >> 1)
	if total > maxInt {
		return int(maxInt)
	}
	return int(total)
}

func logDir(path string) string {
	if path == "" {
		return "."
	}
	return filepath.Dir(path)
}
