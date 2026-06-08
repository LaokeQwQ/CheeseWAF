// Package apisec discovers API endpoints and validates API contracts.
package apisec

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Endpoint struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Count        int            `json:"count"`
	Blocked      int            `json:"blocked"`
	LastSeen     time.Time      `json:"last_seen"`
	StatusFamily map[string]int `json:"status_family"`
}

func Discover(entries []storage.LogEntry, cfg config.APIDiscoveryConfig, now time.Time) []Endpoint {
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 500
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Hour
	}
	since := now.Add(-cfg.Window)
	seen := map[string]*Endpoint{}
	processed := 0
	for idx := len(entries) - 1; idx >= 0 && processed < cfg.SampleLimit; idx-- {
		entry := entries[idx]
		if !entry.Timestamp.IsZero() && entry.Timestamp.Before(since) {
			continue
		}
		path := normalizePath(entry.URI)
		if ignored(path, cfg.IgnorePrefixes) {
			continue
		}
		method := strings.ToUpper(empty(entry.Method, http.MethodGet))
		key := method + " " + path
		item := seen[key]
		if item == nil {
			item = &Endpoint{Method: method, Path: path, StatusFamily: map[string]int{}}
			seen[key] = item
		}
		item.Count++
		if entry.Action == "block" {
			item.Blocked++
		}
		if entry.Timestamp.After(item.LastSeen) {
			item.LastSeen = entry.Timestamp
		}
		item.StatusFamily[statusFamily(entry.StatusCode)]++
		processed++
	}
	out := make([]Endpoint, 0, len(seen))
	for _, item := range seen {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Path < out[j].Path
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func normalizePath(uri string) string {
	path := strings.Split(uri, "?")[0]
	if path == "" {
		path = "/"
	}
	parts := strings.Split(path, "/")
	for idx, part := range parts {
		if part == "" {
			continue
		}
		if looksVariable(part) {
			parts[idx] = "{id}"
		}
	}
	return strings.Join(parts, "/")
}

func looksVariable(part string) bool {
	if len(part) >= 16 {
		return true
	}
	digits := 0
	for _, r := range part {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits > 0 && digits*2 >= len(part)
}

func ignored(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func statusFamily(code int) string {
	if code == 0 {
		return "unknown"
	}
	return string(rune('0'+(code/100))) + "xx"
}

func empty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
