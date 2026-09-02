package handler

import (
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

const (
	defaultAttackMapAggregateLimit = 250
	maxAttackMapAggregateLimit     = 1000
	maxAttackMapStringLength       = 256
	maxAttackMapURIStringLength    = 2048
)

type attackMapAggregateResponse struct {
	Items       []attackMapAggregate `json:"items"`
	Events      []attackMapEvent     `json:"events"`
	Total       int64                `json:"total"`
	Next        *attackMapCursor     `json:"next,omitempty"`
	HasMore     bool                 `json:"has_more"`
	GeneratedAt time.Time            `json:"generated_at"`
}

type attackMapCursor struct {
	Time time.Time `json:"time"`
	ID   string    `json:"id"`
}

type attackMapAggregate struct {
	Key            string           `json:"key"`
	CountryCode    string           `json:"country_code"`
	Country        string           `json:"country"`
	Continent      string           `json:"continent,omitempty"`
	LocationName   string           `json:"location_name,omitempty"`
	AdminCode      string           `json:"admin_code,omitempty"`
	Precision      string           `json:"precision,omitempty"`
	LocationSource string           `json:"location_source,omitempty"`
	AccuracyRadius float64          `json:"accuracy_radius_km,omitempty"`
	Latitude       float64          `json:"lat,omitempty"`
	Longitude      float64          `json:"lon,omitempty"`
	Mappable       bool             `json:"mappable"`
	Attacks        int              `json:"attacks"`
	Blocked        int              `json:"blocked"`
	Severity       string           `json:"severity"`
	SeverityRank   int              `json:"severity_rank"`
	TopCategory    string           `json:"top_category"`
	Categories     map[string]int   `json:"categories,omitempty"`
	SourcePrefixes map[string]int   `json:"source_prefixes,omitempty"`
	Events         []attackMapEvent `json:"events,omitempty"`
}

type attackMapEvent struct {
	ID         string         `json:"id"`
	TraceID    string         `json:"trace_id,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	ClientIP   string         `json:"client_ip,omitempty"`
	Method     string         `json:"method,omitempty"`
	URI        string         `json:"uri,omitempty"`
	Action     string         `json:"action,omitempty"`
	Category   string         `json:"category,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	StatusCode int            `json:"status_code,omitempty"`
	Country    string         `json:"country,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// AttackMapAggregate returns bounded, incremental security-event projections
// for the map views. It deliberately omits payload, user-agent, and arbitrary
// metadata so a frequently refreshed display cannot pull large evidence blobs.
func (h *Handler) AttackMapAggregate(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = defaultAttackMapAggregateLimit
	}
	if limit > maxAttackMapAggregateLimit {
		limit = maxAttackMapAggregateLimit
	}
	after, ok := parseLogTimeQuery(w, r, "after")
	if !ok {
		return
	}
	if h.Sink == nil {
		writeData(w, attackMapAggregateResponse{Items: []attackMapAggregate{}, Events: []attackMapEvent{}, GeneratedAt: time.Now().UTC()})
		return
	}
	afterID := strings.TrimSpace(r.URL.Query().Get("after_id"))
	incremental := !after.IsZero() || afterID != ""
	entries, total, err := h.Sink.Query(r.Context(), storage.LogFilter{
		Kind:      "security",
		AfterTime: after,
		AfterID:   afterID,
		Ascending: incremental,
		Limit:     limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LOG_QUERY_ERROR", err.Error())
		return
	}
	h.enrichLogGeo(entries)
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Timestamp.Equal(entries[j].Timestamp) {
			return logEntryID(entries[i]) < logEntryID(entries[j])
		}
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})
	items := aggregateAttackMapEntries(entries)
	response := attackMapAggregateResponse{
		Items:       items,
		Events:      make([]attackMapEvent, 0, len(entries)),
		Total:       total,
		HasMore:     len(entries) == limit,
		GeneratedAt: time.Now().UTC(),
	}
	for _, entry := range entries {
		response.Events = append(response.Events, projectAttackMapEvent(entry))
	}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		response.Next = &attackMapCursor{Time: last.Timestamp, ID: logEntryID(last)}
	}
	writeData(w, response)
}

func aggregateAttackMapEntries(entries []storage.LogEntry) []attackMapAggregate {
	byKey := make(map[string]*attackMapAggregate)
	for _, entry := range entries {
		country := boundedAttackMapString(entry.Country, maxAttackMapStringLength)
		continent := ""
		locationName := ""
		adminCode := ""
		precision := ""
		locationSource := ""
		lat, lon := 0.0, 0.0
		accuracy := 0.0
		if entry.Metadata != nil {
			country = firstString(country, metadataString(entry.Metadata, "country_code", "countryCode", "geo.country_code"))
			continent = metadataString(entry.Metadata, "continent", "continent_name", "geo.continent")
			locationName = metadataString(entry.Metadata, "city", "city_name", "region", "region_name", "geo.city", "geo.region")
			adminCode = metadataString(entry.Metadata, "admin_code", "adminCode", "adcode", "geo.admin_code")
			precision = metadataString(entry.Metadata, "precision", "geo.precision")
			locationSource = metadataString(entry.Metadata, "source", "geo.source")
			lat = metadataFloat(entry.Metadata, "lat", "latitude", "geo.lat", "geo.latitude")
			lon = metadataFloat(entry.Metadata, "lon", "lng", "longitude", "geo.lon", "geo.longitude")
			accuracy = metadataFloat(entry.Metadata, "accuracy_radius", "accuracy", "geo.accuracy_radius")
		}
		country = strings.ToUpper(boundedAttackMapString(country, maxAttackMapStringLength))
		if country == "" {
			country = "UNLOCATED"
		}
		prefix := sourceIPPrefix(entry.ClientIP)
		key := strings.Join([]string{country, adminCode, locationName, prefix}, "|")
		item := byKey[key]
		if item == nil {
			item = &attackMapAggregate{
				Key:            key,
				CountryCode:    country,
				Country:        country,
				Continent:      continent,
				LocationName:   locationName,
				AdminCode:      adminCode,
				Precision:      precision,
				LocationSource: locationSource,
				AccuracyRadius: accuracy,
				Latitude:       lat,
				Longitude:      lon,
				Mappable:       validMapCoordinate(lat, lon),
				Categories:     map[string]int{},
				SourcePrefixes: map[string]int{},
			}
			byKey[key] = item
		}
		item.Attacks++
		category := strings.TrimSpace(entry.Category)
		if category == "" {
			category = strings.TrimSpace(entry.Action)
		}
		if category == "" {
			category = "unknown"
		}
		item.Categories[category]++
		if prefix != "" {
			item.SourcePrefixes[prefix]++
		}
		if strings.EqualFold(entry.Action, "block") || entry.StatusCode == http.StatusForbidden {
			item.Blocked++
		}
		severity := strings.ToLower(strings.TrimSpace(entry.Severity))
		if severity == "" {
			severity = "medium"
		}
		if rank := mapSeverityRank(severity); rank > item.SeverityRank {
			item.SeverityRank = rank
			item.Severity = severity
		}
		item.Events = retainLatestAttackMapEvents(item.Events, projectAttackMapEvent(entry), 6)
	}
	out := make([]attackMapAggregate, 0, len(byKey))
	for _, item := range byKey {
		item.TopCategory = topMapCategory(item.Categories)
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Attacks > out[j].Attacks || (out[i].Attacks == out[j].Attacks && out[i].Key < out[j].Key)
	})
	return out
}

func retainLatestAttackMapEvents(events []attackMapEvent, event attackMapEvent, limit int) []attackMapEvent {
	if limit <= 0 {
		return nil
	}
	events = append(events, event)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].ID > events[j].ID
		}
		return events[i].Timestamp.After(events[j].Timestamp)
	})
	if len(events) > limit {
		events = events[:limit]
	}
	return events
}

func projectAttackMapEvent(entry storage.LogEntry) attackMapEvent {
	metadata := compactAttackMapMetadata(entry.Metadata)
	return attackMapEvent{
		ID: entry.ID, TraceID: boundedAttackMapString(entry.TraceID, maxAttackMapStringLength), Timestamp: entry.Timestamp,
		ClientIP: boundedAttackMapString(entry.ClientIP, maxAttackMapStringLength), Method: boundedAttackMapString(entry.Method, 32), URI: boundedAttackMapString(entry.URI, maxAttackMapURIStringLength),
		Action: boundedAttackMapString(entry.Action, 64), Category: boundedAttackMapString(entry.Category, maxAttackMapStringLength), Severity: boundedAttackMapString(entry.Severity, 64),
		StatusCode: entry.StatusCode,
		Country:    boundedAttackMapString(entry.Country, maxAttackMapStringLength),
		Metadata:   metadata,
	}
}

func compactAttackMapMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	out := make(map[string]any)
	for _, key := range []string{
		"country_code", "country_name", "continent", "city", "region", "district", "street",
		"region_code", "district_code", "street_code", "admin_code", "adcode",
		"lat", "lon", "latitude", "longitude", "accuracy_radius", "precision", "source",
		"server_lat", "server_lon", "server_latitude", "server_longitude", "server_region",
		"origin_lat", "origin_lon", "origin_latitude", "origin_longitude", "origin_region",
		"target_lat", "target_lon", "target_latitude", "target_longitude", "target_region",
	} {
		if value, ok := compactAttackMapValue(metadata[key]); ok {
			out[key] = value
		}
	}
	if geo, ok := metadata["geo"].(map[string]any); ok {
		for _, key := range []string{
			"country_code", "country_name", "continent", "city", "region", "district", "street",
			"region_code", "district_code", "street_code", "admin_code", "adcode",
			"lat", "lon", "latitude", "longitude", "accuracy_radius", "precision", "source",
		} {
			if value, exists := compactAttackMapValue(geo[key]); exists {
				out[key] = value
			}
		}
	}
	for _, namespace := range []string{"server", "origin", "target"} {
		location, ok := metadata[namespace].(map[string]any)
		if !ok {
			continue
		}
		projected := make(map[string]any)
		for _, key := range []string{"lat", "lon", "lng", "latitude", "longitude", "region", "city"} {
			if value, exists := compactAttackMapValue(location[key]); exists {
				projected[key] = value
			}
		}
		if len(projected) > 0 {
			out[namespace] = projected
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func compactAttackMapValue(value any) (any, bool) {
	switch typed := value.(type) {
	case float32:
		if math.IsNaN(float64(typed)) || math.IsInf(float64(typed), 0) {
			return nil, false
		}
		return value, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, false
		}
		return value, true
	case string:
		return boundedAttackMapString(typed, maxAttackMapStringLength), true
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return value, true
	default:
		return nil, false
	}
}

func boundedAttackMapString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	runes := []rune(value)
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}

func metadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := metadataValue(metadata, key).(string); ok && strings.TrimSpace(value) != "" {
			return boundedAttackMapString(value, maxAttackMapStringLength)
		}
	}
	return ""
}

func metadataFloat(metadata map[string]any, keys ...string) float64 {
	for _, key := range keys {
		var parsed float64
		switch value := metadataValue(metadata, key).(type) {
		case float64:
			parsed = value
		case float32:
			parsed = float64(value)
		case int:
			parsed = float64(value)
		case string:
			number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				continue
			}
			parsed = number
		default:
			continue
		}
		if !math.IsNaN(parsed) && !math.IsInf(parsed, 0) {
			return parsed
		}
	}
	return 0
}

func metadataValue(metadata map[string]any, key string) any {
	if value, ok := metadata[key]; ok {
		return value
	}
	parts := strings.Split(key, ".")
	var current any = metadata
	for _, part := range parts {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[part]
		if !ok {
			return nil
		}
	}
	return current
}

func validMapCoordinate(lat, lon float64) bool {
	return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 && (lat != 0 || lon != 0)
}

func firstString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sourceIPPrefix(value string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	address = address.Unmap()
	bits := 64
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}

func mapSeverityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "warning":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func topMapCategory(categories map[string]int) string {
	top := ""
	count := 0
	for category, value := range categories {
		if value > count || (value == count && category < top) {
			top, count = category, value
		}
	}
	return top
}

func logEntryID(entry storage.LogEntry) string {
	if entry.ID != "" {
		return entry.ID
	}
	return entry.TraceID
}
