package handler

import (
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type uiErrorReportRequest struct {
	TraceID        string     `json:"trace_id"`
	Name           string     `json:"name"`
	Message        string     `json:"message"`
	Stack          string     `json:"stack"`
	ComponentStack string     `json:"component_stack"`
	Path           string     `json:"path"`
	UserAgent      string     `json:"user_agent"`
	Language       string     `json:"language"`
	Viewport       uiViewport `json:"viewport"`
}

type uiViewport struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

func (h *Handler) ReportUIError(w http.ResponseWriter, r *http.Request) {
	var req uiErrorReportRequest
	if !decode(w, r, &req) {
		return
	}
	traceID := normalizeUITraceID(req.TraceID)
	message := truncateForLog(firstNonEmpty(req.Message, req.Name, "frontend UI error"), 512)
	path := truncateForLog(firstNonEmpty(req.Path, "/"), 1024)
	userAgent := truncateForLog(firstNonEmpty(req.UserAgent, r.UserAgent()), 512)

	if h.Sink != nil {
		if err := h.Sink.Write(r.Context(), &storage.LogEntry{
			ID:         traceID,
			Timestamp:  time.Now().UTC(),
			TraceID:    traceID,
			SiteID:     "admin-console",
			ClientIP:   engine.ClientIP(r),
			Method:     "UI",
			URI:        path,
			Action:     "error",
			DetectorID: "ui.error_boundary",
			Category:   "ui_error",
			Severity:   "medium",
			Message:    message,
			Payload:    truncateForLog(req.Name, 128),
			UserAgent:  userAgent,
			Metadata: map[string]any{
				"error_name":      truncateForLog(req.Name, 128),
				"stack":           truncateForLog(req.Stack, 8192),
				"component_stack": truncateForLog(req.ComponentStack, 8192),
				"path":            path,
				"language":        truncateForLog(req.Language, 64),
				"viewport_width":  req.Viewport.Width,
				"viewport_height": req.Viewport.Height,
				"source":          "admin_console",
			},
		}); err != nil {
			writeErrorWithTraceID(w, http.StatusInternalServerError, "UI_ERROR_REPORT_FAILED", err.Error(), traceID)
			return
		}
	}

	w.Header().Set("X-CheeseWAF-Trace-ID", traceID)
	writeData(w, map[string]any{"trace_id": traceID, "recorded": h.Sink != nil})
}

func normalizeUITraceID(raw string) string {
	traceID := strings.TrimSpace(raw)
	if traceID == "" || utf8.RuneCountInString(traceID) > 128 {
		return blockpage.NewTraceID()
	}
	for _, item := range traceID {
		if item >= 'a' && item <= 'z' || item >= 'A' && item <= 'Z' || item >= '0' && item <= '9' || item == '-' || item == '_' || item == '.' {
			continue
		}
		return blockpage.NewTraceID()
	}
	return traceID
}

func truncateForLog(value string, maxRunes int) string {
	value = strings.TrimSpace(value)
	if maxRunes <= 0 || utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return string(runes[:maxRunes]) + "...(truncated)"
}
