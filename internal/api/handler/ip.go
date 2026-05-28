package handler

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	ipprotect "github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/google/uuid"
)

type threatIntelImportPayload struct {
	Format    string   `json:"format"`
	Contents  string   `json:"contents"`
	Source    string   `json:"source"`
	Severity  string   `json:"severity"`
	Action    string   `json:"action"`
	Labels    []string `json:"labels"`
	ExpiresAt string   `json:"expires_at"`
}

type threatIntelSyncPayload struct {
	ProviderID string `json:"provider_id"`
}

type threatIntelLookupPayload struct {
	ProviderID string `json:"provider_id"`
	IP         string `json:"ip"`
}

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
		"providers":    h.Config.Protection.IP.Providers,
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
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
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
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, h.Config.Protection.IP.Tags)
}

func (h *Handler) UpdateThreatIntelProviders(w http.ResponseWriter, r *http.Request) {
	var req []config.ThreatIntelProviderConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.IP.Providers = req
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, h.Config.Protection.IP.Providers)
}

func (h *Handler) ImportThreatIntel(w http.ResponseWriter, r *http.Request) {
	var req threatIntelImportPayload
	if !decode(w, r, &req) {
		return
	}
	expiresAt, err := parseOptionalTime(req.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}
	imported, err := ipprotect.ParseThreatIntel(req.Format, []byte(req.Contents), ipprotect.ImportOptions{
		Source:    req.Source,
		Severity:  req.Severity,
		Action:    req.Action,
		Labels:    req.Labels,
		ExpiresAt: expiresAt,
		Enabled:   true,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "THREAT_INTEL_IMPORT_ERROR", err.Error())
		return
	}
	h.Config.Protection.IP.ThreatIntel = ipprotect.MergeThreatIntel(h.Config.Protection.IP.ThreatIntel, imported)
	if err := h.persistConfig(); err != nil {
		writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"imported": len(imported), "total": len(h.Config.Protection.IP.ThreatIntel)})
}

func (h *Handler) SyncThreatIntel(w http.ResponseWriter, r *http.Request) {
	var req threatIntelSyncPayload
	if r.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(bytes.TrimSpace(body)) > 0 {
			_ = json.Unmarshal(body, &req)
		}
	}
	providers := selectedProviders(h.Config.Protection.IP.Providers, req.ProviderID)
	var total int
	results := make([]map[string]any, 0, len(providers))
	for _, provider := range providers {
		imported, err := fetchProvider(r.Context(), provider)
		result := map[string]any{"provider_id": provider.ID, "name": provider.Name}
		if err != nil {
			result["ok"] = false
			result["error"] = err.Error()
			results = append(results, result)
			continue
		}
		h.Config.Protection.IP.ThreatIntel = ipprotect.MergeThreatIntel(h.Config.Protection.IP.ThreatIntel, imported)
		total += len(imported)
		result["ok"] = true
		result["imported"] = len(imported)
		results = append(results, result)
	}
	if total > 0 {
		if err := h.persistConfig(); err != nil {
			writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
			return
		}
	}
	writeData(w, map[string]any{"imported": total, "results": results, "total": len(h.Config.Protection.IP.ThreatIntel)})
}

func (h *Handler) TestThreatIntelProvider(w http.ResponseWriter, r *http.Request) {
	var provider config.ThreatIntelProviderConfig
	if !decode(w, r, &provider) {
		return
	}
	imported, err := fetchProvider(r.Context(), provider)
	if err != nil {
		writeError(w, http.StatusBadRequest, "THREAT_INTEL_PROVIDER_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"ok": true, "count": len(imported)})
}

func (h *Handler) LookupThreatIntel(w http.ResponseWriter, r *http.Request) {
	var req threatIntelLookupPayload
	if !decode(w, r, &req) {
		return
	}
	providers := selectedProviders(h.Config.Protection.IP.Providers, req.ProviderID)
	if len(providers) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "provider not found")
		return
	}
	var imported []config.ThreatIntelConfig
	for _, provider := range providers {
		items, err := lookupProviderIP(r.Context(), provider, req.IP)
		if err != nil {
			writeError(w, http.StatusBadRequest, "THREAT_INTEL_LOOKUP_ERROR", err.Error())
			return
		}
		imported = append(imported, items...)
	}
	if len(imported) > 0 {
		h.Config.Protection.IP.ThreatIntel = ipprotect.MergeThreatIntel(h.Config.Protection.IP.ThreatIntel, imported)
		if err := h.persistConfig(); err != nil {
			writeError(w, http.StatusInternalServerError, "CONFIG_SAVE_ERROR", err.Error())
			return
		}
	}
	writeData(w, map[string]any{"ip": req.IP, "imported": len(imported), "items": imported})
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
	_ = h.persistConfig()
	writeData(w, h.Config.Protection.ACL)
}

func (h *Handler) UpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	var req config.RateLimitProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.RateLimit = req
	_ = h.persistConfig()
	writeData(w, h.Config.Protection.RateLimit)
}

func (h *Handler) UpdateBotProtection(w http.ResponseWriter, r *http.Request) {
	var req config.BotProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	h.Config.Protection.Bot = req
	_ = h.persistConfig()
	writeData(w, h.Config.Protection.Bot)
}

func selectedProviders(providers []config.ThreatIntelProviderConfig, id string) []config.ThreatIntelProviderConfig {
	var out []config.ThreatIntelProviderConfig
	for _, provider := range providers {
		if !provider.Enabled {
			continue
		}
		if id != "" && provider.ID != id {
			continue
		}
		out = append(out, provider)
	}
	return out
}

func fetchProvider(ctx context.Context, provider config.ThreatIntelProviderConfig) ([]config.ThreatIntelConfig, error) {
	if provider.Endpoint == "" {
		return nil, fmt.Errorf("provider endpoint is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.Endpoint, nil)
	if err != nil {
		return nil, err
	}
	applyProviderAuth(req, provider)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, err
	}
	return ipprotect.ParseThreatIntel(provider.Format, body, ipprotect.ImportOptions{
		Source:   emptyString(provider.Name, provider.ID),
		Severity: provider.MinSeverity,
		Action:   provider.Action,
		Enabled:  true,
	})
}

func lookupProviderIP(ctx context.Context, provider config.ThreatIntelProviderConfig, ip string) ([]config.ThreatIntelConfig, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid ip %q", ip)
	}
	endpoint := provider.Endpoint
	if endpoint == "" {
		switch strings.ToLower(provider.Type) {
		case "threatbook", "threatbook-cn":
			endpoint = "https://api.threatbook.cn/v3/ip/query"
		case "threatbook-intl":
			endpoint = "https://api.threatbook.io/v2/ip/query"
		default:
			return nil, fmt.Errorf("provider endpoint is required")
		}
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	switch strings.ToLower(provider.Type) {
	case "threatbook", "threatbook-cn":
		if provider.APIKey != "" {
			query.Set("apikey", provider.APIKey)
		}
		query.Set("resource", ip)
	default:
		query.Set("ip", ip)
	}
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	applyProviderAuth(req, provider)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	format := provider.Format
	if format == "" {
		format = "threatbook"
	}
	items, err := ipprotect.ParseThreatIntel(format, body, ipprotect.ImportOptions{
		Source:   emptyString(provider.Name, provider.ID),
		Severity: provider.MinSeverity,
		Action:   provider.Action,
		Enabled:  true,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		items = append(items, config.ThreatIntelConfig{
			ID:       "intel-" + uuid.NewSHA1(uuid.NameSpaceURL, []byte(provider.ID+":"+ip)).String(),
			Value:    ip,
			Type:     "ip",
			Severity: "medium",
			Source:   emptyString(provider.Name, provider.ID),
			Action:   emptyString(provider.Action, "challenge"),
			Enabled:  true,
		})
	}
	return items, nil
}

func applyProviderAuth(req *http.Request, provider config.ThreatIntelProviderConfig) {
	for key, value := range provider.Headers {
		req.Header.Set(key, value)
	}
	if provider.APIKey != "" {
		if req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", "Bearer "+provider.APIKey)
		}
		if req.Header.Get("X-API-Key") == "" {
			req.Header.Set("X-API-Key", provider.APIKey)
		}
	}
}

func parseOptionalTime(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

func emptyString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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
