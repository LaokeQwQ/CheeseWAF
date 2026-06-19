package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	protectionip "github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
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
	h.enrichLogGeo(entries)
	writeData(w, map[string]any{"items": entries, "total": total})
}

func (h *Handler) enrichLogGeo(entries []storage.LogEntry) {
	if h == nil || h.Config == nil || len(entries) == 0 {
		return
	}
	h.geoipMu.Lock()
	defer h.geoipMu.Unlock()
	policy, err := h.logGeoIPPolicyLocked()
	if err != nil || policy == nil {
		return
	}
	for index := range entries {
		entry := &entries[index]
		if !needsGeoEnrichment(entry) {
			continue
		}
		location := policy.Lookup(entry.ClientIP)
		metadata := location.Metadata()
		if location.CountryCode == "" && len(metadata) == 0 {
			continue
		}
		if entry.Country == "" || isUnknownGeoToken(entry.Country) {
			entry.Country = location.CountryCode
		}
		if entry.Metadata == nil {
			entry.Metadata = map[string]any{}
		}
		entry.Metadata["geo"] = metadata
	}
}

func (h *Handler) logGeoIPPolicyLocked() (*protectionip.GeoIPPolicy, error) {
	raw, _ := json.Marshal(h.Config.Protection.IP.GeoIP)
	key := string(raw)
	if h.geoipPolicy != nil && h.geoipCacheKey == key {
		return h.geoipPolicy, nil
	}
	if h.geoipErrorKey == key && time.Now().Before(h.geoipRetryAfter) {
		return nil, nil
	}
	if h.geoipPolicy != nil {
		_ = h.geoipPolicy.Close()
		h.geoipPolicy = nil
	}
	policy, err := protectionip.NewGeoIPPolicy(h.Config.Protection.IP.GeoIP)
	if err != nil {
		h.geoipErrorKey = key
		h.geoipRetryAfter = time.Now().Add(30 * time.Second)
		return nil, err
	}
	h.geoipPolicy = policy
	h.geoipCacheKey = key
	h.geoipErrorKey = ""
	h.geoipRetryAfter = time.Time{}
	return policy, nil
}

func needsGeoEnrichment(entry *storage.LogEntry) bool {
	if entry == nil || isPrivateOrReservedLogIP(entry.ClientIP) {
		return false
	}
	if !isUnknownGeoToken(entry.Country) {
		if geo, ok := entry.Metadata["geo"]; ok {
			if nested, ok := geo.(map[string]any); ok && len(nested) > 0 {
				return false
			}
		}
	}
	return true
}

func isUnknownGeoToken(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "", "-", "UNKNOWN", "UNLOCATED":
		return true
	default:
		return false
	}
}

func isPrivateOrReservedLogIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		first, second := ipv4[0], ipv4[1]
		return first == 0 ||
			first == 127 ||
			(first == 100 && second >= 64 && second <= 127) ||
			(first == 169 && second == 254) ||
			(first == 192 && second == 0) ||
			(first == 198 && second == 51 && ipv4[2] == 100) ||
			(first == 198 && (second == 18 || second == 19)) ||
			(first == 203 && second == 0 && ipv4[2] == 113) ||
			first >= 224
	}
	if ip.IsInterfaceLocalMulticast() {
		return true
	}
	return len(ip) == net.IPv6len && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8
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
