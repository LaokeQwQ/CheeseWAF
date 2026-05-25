package handler

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	ipprotect "github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/google/uuid"
)

func (h *Handler) ListIPRules(w http.ResponseWriter, r *http.Request) {
	var logs []storage.LogEntry
	if h.Sink != nil {
		items, _, err := h.Sink.Query(r.Context(), storage.LogFilter{Limit: 500})
		if err == nil {
			logs = items
		}
	}
	profiles, err := ipprotect.BuildReputationProfiles(h.Config.Protection.IP, logs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IP_POLICY_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{
		"whitelist":    h.Config.Protection.IP.Whitelist,
		"blacklist":    h.Config.Protection.IP.Blacklist,
		"tags":         h.Config.Protection.IP.Tags,
		"threat_intel": h.Config.Protection.IP.ThreatIntel,
		"geoip":        h.Config.Protection.IP.GeoIP,
		"entries":      profiles,
	})
}

func (h *Handler) Protection(w http.ResponseWriter, _ *http.Request) {
	writeData(w, h.Config.Protection)
}

func (h *Handler) UpdateIPRules(w http.ResponseWriter, r *http.Request) {
	var req config.IPProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.IP = req
	writeData(w, h.Config.Protection.IP)
}

func (h *Handler) UpdateIPTags(w http.ResponseWriter, r *http.Request) {
	var req map[string][]string
	if !decode(w, r, &req) {
		return
	}
	tagger := ipprotect.NewTagger(h.Config.Protection.IP.Tags)
	for ip, tags := range req {
		tagger.Set(ip, tags)
	}
	h.Config.Protection.IP.Tags = tagger.Snapshot()
	writeData(w, h.Config.Protection.IP.Tags)
}

func (h *Handler) ExportThreatIntel(w http.ResponseWriter, r *http.Request) {
	profiles, err := ipprotect.BuildReputationProfiles(h.Config.Protection.IP, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "IP_POLICY_ERROR", err.Error())
		return
	}
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "stix":
		w.Header().Set("Content-Type", "application/stix+json")
		_ = json.NewEncoder(w).Encode(stixBundle(profiles))
	default:
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="cheesewaf-threat-intel.csv"`)
		writer := csv.NewWriter(w)
		_ = writer.Write([]string{"ip", "list", "reputation", "tags", "intel"})
		for _, profile := range profiles {
			if profile.List == "monitor" && len(profile.Tags) == 0 && len(profile.Intel) == 0 {
				continue
			}
			_ = writer.Write([]string{profile.IP, profile.List, intString(profile.Reputation), strings.Join(profile.Tags, "|"), intelSummary(profile.Intel)})
		}
		writer.Flush()
	}
}

func (h *Handler) UpdateACLRules(w http.ResponseWriter, r *http.Request) {
	var req config.ACLProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.ACL = req
	writeData(w, h.Config.Protection.ACL)
}

func (h *Handler) UpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	var req config.RateLimitProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.RateLimit = req
	writeData(w, h.Config.Protection.RateLimit)
}

func (h *Handler) UpdateBotProtection(w http.ResponseWriter, r *http.Request) {
	var req config.BotProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.Bot = req
	writeData(w, h.Config.Protection.Bot)
}

func stixBundle(profiles []ipprotect.ReputationProfile) map[string]any {
	objects := make([]map[string]any, 0, len(profiles))
	for _, profile := range profiles {
		if profile.List == "monitor" && len(profile.Tags) == 0 && len(profile.Intel) == 0 {
			continue
		}
		objects = append(objects, map[string]any{
			"type":         "indicator",
			"id":           "indicator--" + uuid.NewSHA1(uuid.NameSpaceURL, []byte(profile.IP)).String(),
			"name":         "CheeseWAF " + profile.IP,
			"pattern":      stixIPPattern(profile.IP),
			"pattern_type": "stix",
			"labels":       append([]string{profile.List}, profile.Tags...),
		})
	}
	return map[string]any{
		"type":    "bundle",
		"id":      "bundle--cheesewaf-threat-intel",
		"objects": objects,
	}
}

func intelSummary(items []ipprotect.Indicator) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, item.Source+":"+item.Severity)
	}
	return strings.Join(parts, "|")
}

func stixIPPattern(value string) string {
	if strings.Contains(value, "/") {
		return "[ipv4-addr:value ISSUBSET '" + value + "']"
	}
	return "[ipv4-addr:value = '" + value + "']"
}

func intString(value int) string {
	return strconv.Itoa(value)
}
