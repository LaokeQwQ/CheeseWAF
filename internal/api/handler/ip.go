package handler

import (
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
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
	ipprotect "github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/google/uuid"
)

const (
	threatIntelHTTPTimeout          = 15 * time.Second
	threatIntelProviderMaxBodyBytes = 20 << 20
	threatIntelLookupMaxBodyBytes   = 4 << 20
)

var (
	threatIntelResolveIP            = net.DefaultResolver.LookupIP
	threatIntelProviderURLValidator = validateThreatIntelProviderURL
	threatIntelHTTPClient           = newThreatIntelHTTPClient(threatIntelHTTPTimeout)
)

type threatIntelImportPayload struct {
	Format     string   `json:"format"`
	Contents   string   `json:"contents"`
	Source     string   `json:"source"`
	Severity   string   `json:"severity"`
	Action     string   `json:"action"`
	Confidence float64  `json:"confidence"`
	Labels     []string `json:"labels"`
	ExpiresAt  string   `json:"expires_at"`
}

type threatIntelSyncPayload struct {
	ProviderID string `json:"provider_id"`
}

type threatIntelTestPayload struct {
	ProviderID string `json:"provider_id"`
	config.ThreatIntelProviderConfig
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
	view := protectionConfigView(h.Config.Protection)
	writeData(w, map[string]any{
		"whitelist":            view.IP.Whitelist,
		"blacklist":            view.IP.Blacklist,
		"access_rules":         view.IP.AccessRules,
		"reputation_overrides": view.IP.ReputationOverrides,
		"tags":                 view.IP.Tags,
		"threat_intel":         view.IP.ThreatIntel,
		"providers":            view.IP.Providers,
		"geoip":                view.IP.GeoIP,
		"entries":              profiles,
	})
}

func (h *Handler) Protection(w http.ResponseWriter, _ *http.Request) {
	writeData(w, protectionConfigView(h.Config.Protection))
}

func (h *Handler) commitProtectionMutation(w http.ResponseWriter, mutate func(*config.ProtectionConfig) error) (*config.Config, bool) {
	committed, err := h.commitConfigMutation(func(candidate *config.Config) error {
		return mutate(&candidate.Protection)
	}, func(candidate *config.Config) error {
		return h.notifyProtectionConfigChanged(candidate.Protection)
	})
	if err == nil {
		return committed, true
	}
	code := "CONFIG_SAVE_ERROR"
	if strings.HasPrefix(err.Error(), "apply runtime config:") {
		code = "PROTECTION_RELOAD_ERROR"
	}
	writeError(w, http.StatusInternalServerError, code, err.Error())
	return nil, false
}

func (h *Handler) UpdateProtectionPolicy(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.ProtectionPolicyConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		current := next.Policy.WithDefaults(config.DefaultProtectionPolicy())
		next.Policy = req.WithDefaults(current)
		return nil
	})
	if !ok {
		return
	}
	writeData(w, committed.Protection.Policy)
}

func (h *Handler) UpdateIPRules(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.IPProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		req.Providers = preserveThreatIntelProviderSecrets(next.IP.Providers, req.Providers)
		next.IP = req
		return nil
	})
	if !ok {
		return
	}
	writeData(w, protectionConfigView(committed.Protection).IP)
}

func (h *Handler) UpdateIPAccessRules(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req []config.IPAccessRuleConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		next.IP.AccessRules = req
		return nil
	})
	if !ok {
		return
	}
	writeData(w, committed.Protection.IP.AccessRules)
}

func (h *Handler) UpdateIPReputationOverrides(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req map[string]int
	if !decode(w, r, &req) {
		return
	}
	if req == nil {
		req = map[string]int{}
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		next.IP.ReputationOverrides = req
		return nil
	})
	if !ok {
		return
	}
	writeData(w, committed.Protection.IP.ReputationOverrides)
}

func (h *Handler) UpdateIPTags(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req map[string][]string
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		tagger := ipprotect.NewTagger(next.IP.Tags)
		for ip, tags := range req {
			tagger.Set(ip, tags)
		}
		next.IP.Tags = tagger.Snapshot()
		return nil
	})
	if !ok {
		return
	}
	writeData(w, committed.Protection.IP.Tags)
}

func (h *Handler) UpdateThreatIntelProviders(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req []config.ThreatIntelProviderConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		next.IP.Providers = preserveThreatIntelProviderSecrets(next.IP.Providers, req)
		return nil
	})
	if !ok {
		return
	}
	writeData(w, protectionConfigView(committed.Protection).IP.Providers)
}

func (h *Handler) ImportThreatIntel(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
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
		Source:     req.Source,
		Severity:   req.Severity,
		Action:     req.Action,
		Confidence: req.Confidence,
		Labels:     req.Labels,
		ExpiresAt:  expiresAt,
		Enabled:    true,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "THREAT_INTEL_IMPORT_ERROR", err.Error())
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		next.IP.ThreatIntel = ipprotect.MergeThreatIntel(next.IP.ThreatIntel, imported)
		return nil
	})
	if !ok {
		return
	}
	writeData(w, map[string]any{"imported": len(imported), "total": len(committed.Protection.IP.ThreatIntel)})
}

func (h *Handler) SyncThreatIntel(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req threatIntelSyncPayload
	if !decodeOptional(w, r, &req, defaultJSONBodyLimit, "invalid threat intelligence sync request") {
		return
	}
	providers := selectedProviders(h.Config.Protection.IP.Providers, req.ProviderID)
	var total int
	var merged []config.ThreatIntelConfig
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
		total += len(imported)
		merged = append(merged, imported...)
		result["ok"] = true
		result["imported"] = len(imported)
		results = append(results, result)
	}
	finalTotal := len(h.Config.Protection.IP.ThreatIntel)
	if total > 0 {
		committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
			next.IP.ThreatIntel = ipprotect.MergeThreatIntel(next.IP.ThreatIntel, merged)
			return nil
		})
		if !ok {
			return
		}
		finalTotal = len(committed.Protection.IP.ThreatIntel)
	}
	writeData(w, map[string]any{"imported": total, "results": results, "total": finalTotal})
}

func (h *Handler) TestThreatIntelProvider(w http.ResponseWriter, r *http.Request) {
	var req threatIntelTestPayload
	if !decode(w, r, &req) {
		return
	}
	provider := resolveThreatIntelProviderForTest(h.Config.Protection.IP.Providers, req.ThreatIntelProviderConfig, req.ProviderID)
	if strings.TrimSpace(provider.Endpoint) == "" && strings.TrimSpace(req.ProviderID) != "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "provider not found")
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
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
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
		_, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
			next.IP.ThreatIntel = ipprotect.MergeThreatIntel(next.IP.ThreatIntel, imported)
			return nil
		})
		if !ok {
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
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.ACLProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		next.ACL = req
		return nil
	})
	if !ok {
		return
	}
	writeData(w, committed.Protection.ACL)
}

func (h *Handler) UpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.RateLimitProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		next.RateLimit = req
		return nil
	})
	if !ok {
		return
	}
	writeData(w, committed.Protection.RateLimit)
}

func (h *Handler) UpdateBotProtection(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req config.BotProtectionConfig
	if !decode(w, r, &req) {
		return
	}
	committed, ok := h.commitProtectionMutation(w, func(next *config.ProtectionConfig) error {
		if req.Secret == "" {
			req.Secret = next.Bot.Secret
		}
		next.Bot = req
		return nil
	})
	if !ok {
		return
	}
	writeData(w, protectionConfigView(committed.Protection).Bot)
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

func resolveThreatIntelProviderForTest(current []config.ThreatIntelProviderConfig, submitted config.ThreatIntelProviderConfig, providerID string) config.ThreatIntelProviderConfig {
	id := strings.TrimSpace(providerID)
	if id == "" {
		id = strings.TrimSpace(submitted.ID)
	}
	if id == "" {
		return submitted
	}
	for _, existing := range current {
		if existing.ID != id {
			continue
		}
		merged := existing
		overlayThreatIntelProvider(&merged, submitted)
		merged.ID = id
		if submitted.Headers != nil {
			merged.Headers = preserveStringMapSecrets(existing.Headers, submitted.Headers)
		}
		if strings.TrimSpace(submitted.APIKey) == "" {
			merged.APIKey = existing.APIKey
		}
		return merged
	}
	submitted.ID = ""
	return submitted
}

func overlayThreatIntelProvider(base *config.ThreatIntelProviderConfig, submitted config.ThreatIntelProviderConfig) {
	if strings.TrimSpace(submitted.Name) != "" {
		base.Name = submitted.Name
	}
	if strings.TrimSpace(submitted.Type) != "" {
		base.Type = submitted.Type
	}
	if strings.TrimSpace(submitted.Endpoint) != "" {
		base.Endpoint = submitted.Endpoint
	}
	if strings.TrimSpace(submitted.APIKey) != "" {
		base.APIKey = submitted.APIKey
	}
	if strings.TrimSpace(submitted.AuthType) != "" {
		base.AuthType = submitted.AuthType
	}
	if strings.TrimSpace(submitted.Format) != "" {
		base.Format = submitted.Format
	}
	if strings.TrimSpace(submitted.Action) != "" {
		base.Action = submitted.Action
	}
	if strings.TrimSpace(submitted.MinSeverity) != "" {
		base.MinSeverity = submitted.MinSeverity
	}
	if submitted.Interval > 0 {
		base.Interval = submitted.Interval
	}
	if strings.TrimSpace(submitted.Notes) != "" {
		base.Notes = submitted.Notes
	}
	base.Enabled = submitted.Enabled || base.Enabled
}

func fetchProvider(ctx context.Context, provider config.ThreatIntelProviderConfig) ([]config.ThreatIntelConfig, error) {
	if provider.Endpoint == "" {
		return nil, fmt.Errorf("provider endpoint is required")
	}
	endpoint, err := threatIntelProviderURLValidator(provider.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid provider endpoint: %w", err)
	}
	req, err := newThreatIntelRequest(ctx, endpoint, provider)
	if err != nil {
		return nil, err
	}
	resp, err := threatIntelHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	body, err := readLimitedResponseBody(resp.Body, threatIntelProviderMaxBodyBytes, "provider response")
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
	parsed, err := providerLookupURL(provider, ip)
	if err != nil {
		return nil, err
	}
	endpoint, err := threatIntelProviderURLValidator(parsed.String())
	if err != nil {
		return nil, fmt.Errorf("invalid provider endpoint: %w", err)
	}
	req, err := newThreatIntelRequest(ctx, endpoint, provider)
	if err != nil {
		return nil, err
	}
	resp, err := threatIntelHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("provider returned %s", resp.Status)
	}
	body, err := readLimitedResponseBody(resp.Body, threatIntelLookupMaxBodyBytes, "provider lookup response")
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
	return items, nil
}

func readLimitedResponseBody(body io.Reader, maxBytes int64, purpose string) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%s size limit is invalid", purpose)
	}
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", purpose, maxBytes)
	}
	return data, nil
}

func providerLookupURL(provider config.ThreatIntelProviderConfig, ip string) (*url.URL, error) {
	providerType := strings.ToLower(strings.TrimSpace(provider.Type))
	endpoint := strings.TrimSpace(provider.Endpoint)
	if endpoint == "" {
		switch providerType {
		case "threatbook", "threatbook-cn":
			endpoint = "https://api.threatbook.cn/v3/ip/query"
		case "threatbook-intl":
			endpoint = "https://api.threatbook.io/v2/ip/query"
		case "abuseipdb":
			endpoint = "https://api.abuseipdb.com/api/v2/check"
		case "otx", "alienvault-otx":
			kind := "IPv4"
			if parsedIP := net.ParseIP(ip); parsedIP != nil && parsedIP.To4() == nil {
				kind = "IPv6"
			}
			endpoint = "https://otx.alienvault.com/api/v1/indicators/" + kind + "/{ip}/general"
		default:
			return nil, fmt.Errorf("provider endpoint is required")
		}
	}
	endpoint = strings.ReplaceAll(endpoint, "{ip}", url.PathEscape(ip))
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	switch providerType {
	case "threatbook", "threatbook-cn", "threatbook-intl":
		if provider.APIKey != "" && query.Get("apikey") == "" {
			query.Set("apikey", provider.APIKey)
		}
		if query.Get("resource") == "" {
			query.Set("resource", ip)
		}
	case "abuseipdb":
		if query.Get("ipAddress") == "" {
			query.Set("ipAddress", ip)
		}
		if query.Get("maxAgeInDays") == "" {
			query.Set("maxAgeInDays", "90")
		}
	default:
		if !strings.Contains(parsed.Path, ip) && query.Get("ip") == "" {
			query.Set("ip", ip)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed, nil
}

func newThreatIntelRequest(ctx context.Context, endpoint *url.URL, provider config.ThreatIntelProviderConfig) (*http.Request, error) {
	if endpoint == nil {
		return nil, fmt.Errorf("provider endpoint is required")
	}
	validated, err := threatIntelProviderURLValidator(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("invalid provider endpoint: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validated.String(), nil)
	if err != nil {
		return nil, err
	}
	applyProviderAuth(req, provider)
	return req, nil
}

func validateThreatIntelProviderURL(raw string) (*url.URL, error) {
	return netguard.ValidateURL(raw, threatIntelProviderURLPolicy())
}

func threatIntelProviderURLPolicy() netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "provider",
		AllowedSchemes: []string{"http", "https"},
	}
}

func newThreatIntelHTTPClient(timeout time.Duration) *http.Client {
	return netguard.NewHTTPClient(netguard.HTTPClientOptions{
		Timeout: timeout,
		Resolver: func(ctx context.Context, network, host string) ([]net.IP, error) {
			return threatIntelResolveIP(ctx, network, host)
		},
		Policy: netguard.URLPolicy{
			Purpose:        "provider",
			AllowedSchemes: []string{"http", "https"},
		},
	})
}

func applyProviderAuth(req *http.Request, provider config.ThreatIntelProviderConfig) {
	for key, value := range provider.Headers {
		req.Header.Set(key, value)
	}
	if provider.APIKey == "" {
		return
	}
	switch strings.ToLower(strings.TrimSpace(provider.Type)) {
	case "abuseipdb":
		if req.Header.Get("Key") == "" {
			req.Header.Set("Key", provider.APIKey)
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}
		return
	case "otx", "alienvault-otx":
		if req.Header.Get("X-OTX-API-KEY") == "" {
			req.Header.Set("X-OTX-API-KEY", provider.APIKey)
		}
		return
	case "misp":
		if req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", provider.APIKey)
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "application/json")
		}
		return
	case "threatbook", "threatbook-cn", "threatbook-intl":
		if req.URL.Query().Get("apikey") != "" {
			return
		}
	}
	switch strings.ToLower(strings.TrimSpace(provider.AuthType)) {
	case "none":
		return
	case "header":
		if req.Header.Get("X-API-Key") == "" {
			req.Header.Set("X-API-Key", provider.APIKey)
		}
	case "query":
		query := req.URL.Query()
		if query.Get("api_key") == "" {
			query.Set("api_key", provider.APIKey)
			req.URL.RawQuery = query.Encode()
		}
	case "basic":
		if req.Header.Get("Authorization") == "" {
			user, pass, ok := strings.Cut(provider.APIKey, ":")
			if ok {
				req.SetBasicAuth(user, pass)
			}
		}
	default:
		if req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", "Bearer "+provider.APIKey)
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
