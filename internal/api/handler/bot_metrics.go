package handler

import (
	"net/http"
	"strings"
	"time"

	protectionbot "github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
)

type botMetricsResponse struct {
	Range  string                               `json:"range"`
	Bucket string                               `json:"bucket"`
	SiteID string                               `json:"site_id,omitempty"`
	Start  time.Time                            `json:"start"`
	End    time.Time                            `json:"end"`
	Totals protectionbot.ChallengeMetricTotals  `json:"totals"`
	Trend  []protectionbot.ChallengeMetricPoint `json:"trend"`
}

func (h *Handler) BotChallengeMetrics(w http.ResponseWriter, r *http.Request) {
	rangeName, window, bucket, ok := botMetricsWindow(r.URL.Query().Get("range"))
	if !ok {
		writeError(w, http.StatusBadRequest, "BOT_METRICS_RANGE_INVALID", "range must be one of 1h, 6h, 24h, 7d, or 30d")
		return
	}
	end := h.nowUTC()
	start := end.Add(-window)
	siteID := strings.TrimSpace(r.URL.Query().Get("site_id"))
	snapshot := protectionbot.ProcessChallengeMetrics().Snapshot(protectionbot.ChallengeMetricQuery{Start: start, End: end, Site: siteID, Bucket: bucket})
	writeData(w, botMetricsResponse{Range: rangeName, Bucket: bucket.String(), SiteID: siteID, Start: snapshot.Start, End: snapshot.End, Totals: snapshot.Totals, Trend: snapshot.Trend})
}

func botMetricsWindow(raw string) (string, time.Duration, time.Duration, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "24h":
		return "24h", 24 * time.Hour, time.Hour, true
	case "1h":
		return "1h", time.Hour, 5 * time.Minute, true
	case "6h":
		return "6h", 6 * time.Hour, 30 * time.Minute, true
	case "7d":
		return "7d", 7 * 24 * time.Hour, 6 * time.Hour, true
	case "30d":
		return "30d", 30 * 24 * time.Hour, 24 * time.Hour, true
	default:
		return "", 0, 0, false
	}
}
