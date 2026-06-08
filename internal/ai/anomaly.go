package ai

import (
	"fmt"
	"sort"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type TrafficAnomaly struct {
	Key       string    `json:"key"`
	Kind      string    `json:"kind"`
	Count     int       `json:"count"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func DetectAnomalies(entries []storage.LogEntry, window time.Duration, now time.Time) []TrafficAnomaly {
	if window <= 0 {
		window = time.Hour
	}
	since := now.Add(-window)
	byIP := map[string]*TrafficAnomaly{}
	byCategory := map[string]*TrafficAnomaly{}
	for _, entry := range entries {
		if !entry.Timestamp.IsZero() && entry.Timestamp.Before(since) {
			continue
		}
		if entry.ClientIP != "" && (entry.Action == "block" || entry.StatusCode == 429) {
			item := ensureAnomaly(byIP, entry.ClientIP, "source_ip", entry.Timestamp)
			item.Count++
			item.LastSeen = maxTime(item.LastSeen, entry.Timestamp)
		}
		if entry.Category != "" && entry.Action == "block" {
			item := ensureAnomaly(byCategory, entry.Category, "category", entry.Timestamp)
			item.Count++
			item.LastSeen = maxTime(item.LastSeen, entry.Timestamp)
		}
	}
	var out []TrafficAnomaly
	for _, item := range byIP {
		if item.Count >= 5 {
			item.Severity = severityForCount(item.Count)
			item.Message = fmt.Sprintf("%d blocked or rate-limited requests from %s in %s", item.Count, item.Key, window)
			out = append(out, *item)
		}
	}
	for _, item := range byCategory {
		if item.Count >= 10 {
			item.Severity = severityForCount(item.Count)
			item.Message = fmt.Sprintf("%d blocked %s events in %s", item.Count, item.Key, window)
			out = append(out, *item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity == out[j].Severity {
			return out[i].Count > out[j].Count
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func ensureAnomaly(items map[string]*TrafficAnomaly, key, kind string, seen time.Time) *TrafficAnomaly {
	item := items[key]
	if item == nil {
		item = &TrafficAnomaly{Key: key, Kind: kind, FirstSeen: seen, LastSeen: seen}
		items[key] = item
	}
	if item.FirstSeen.IsZero() || (!seen.IsZero() && seen.Before(item.FirstSeen)) {
		item.FirstSeen = seen
	}
	return item
}

func severityForCount(count int) string {
	switch {
	case count >= 50:
		return "critical"
	case count >= 20:
		return "high"
	case count >= 10:
		return "medium"
	default:
		return "low"
	}
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
