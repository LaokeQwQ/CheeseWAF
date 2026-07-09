package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestProtectionAndIPRulesRedactSecrets(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.Bot.Secret = "bot-secret"
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:      "otx",
		Name:    "OTX",
		APIKey:  "provider-secret",
		Headers: map[string]string{"Authorization": "Bearer provider-header-secret"},
		Enabled: true,
	}}
	handler := New(Options{Config: &cfg})

	for _, tc := range []struct {
		name string
		call func(*httptest.ResponseRecorder, *http.Request)
	}{
		{
			name: "protection",
			call: func(w *httptest.ResponseRecorder, r *http.Request) { handler.Protection(w, r) },
		},
		{
			name: "ip",
			call: func(w *httptest.ResponseRecorder, r *http.Request) { handler.ListIPRules(w, r) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/"+tc.name, nil)
			tc.call(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			for _, secret := range []string{"bot-secret", "provider-secret", "provider-header-secret"} {
				if strings.Contains(body, secret) {
					t.Fatalf("%s response leaked secret %q: %s", tc.name, secret, body)
				}
			}
		})
	}
}

func TestProtectionSecretUpdatesPreserveExistingValuesWhenEmpty(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.Bot.Secret = "existing-bot-secret"
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:      "otx",
		Name:    "OTX",
		APIKey:  "existing-provider-secret",
		Headers: map[string]string{"Authorization": "Bearer existing-provider-header"},
		Enabled: true,
	}}
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	nextBot := cfg.Protection.Bot
	nextBot.Secret = ""
	rawBot, _ := json.Marshal(nextBot)
	botRecorder := httptest.NewRecorder()
	botRequest := httptest.NewRequest(http.MethodPut, "/api/protection/bot", bytes.NewReader(rawBot))
	handler.UpdateBotProtection(botRecorder, botRequest)
	if botRecorder.Code != http.StatusOK {
		t.Fatalf("expected bot update ok, code=%d body=%s", botRecorder.Code, botRecorder.Body.String())
	}
	if cfg.Protection.Bot.Secret != "existing-bot-secret" {
		t.Fatalf("empty bot update cleared secret, got %q", cfg.Protection.Bot.Secret)
	}
	if strings.Contains(botRecorder.Body.String(), "existing-bot-secret") {
		t.Fatalf("bot update response leaked secret: %s", botRecorder.Body.String())
	}

	providers := []config.ThreatIntelProviderConfig{{
		ID:      "otx",
		Name:    "OTX",
		APIKey:  "",
		Headers: map[string]string{"Authorization": ""},
		Enabled: true,
	}}
	rawProviders, _ := json.Marshal(providers)
	providerRecorder := httptest.NewRecorder()
	providerRequest := httptest.NewRequest(http.MethodPut, "/api/ip/threat-intel/providers", bytes.NewReader(rawProviders))
	handler.UpdateThreatIntelProviders(providerRecorder, providerRequest)
	if providerRecorder.Code != http.StatusOK {
		t.Fatalf("expected provider update ok, code=%d body=%s", providerRecorder.Code, providerRecorder.Body.String())
	}
	if cfg.Protection.IP.Providers[0].APIKey != "existing-provider-secret" ||
		cfg.Protection.IP.Providers[0].Headers["Authorization"] != "Bearer existing-provider-header" {
		t.Fatalf("empty provider update did not preserve secrets: %+v", cfg.Protection.IP.Providers[0])
	}
	body := providerRecorder.Body.String()
	if strings.Contains(body, "existing-provider-secret") || strings.Contains(body, "existing-provider-header") {
		t.Fatalf("provider update response leaked secret: %s", body)
	}
}

func TestUpdateProtectionPolicyMergesPartialPayload(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.Policy = config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelSmart,
		APISecurity: config.ProtectionLevelHigh,
		BotCC:       config.ProtectionLevelLow,
		ThreatIntel: config.ProtectionLevelStrict,
	}
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var reloaded config.ProtectionConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			reloaded = next
			return nil
		},
	})

	raw, _ := json.Marshal(map[string]string{"web_attack": config.ProtectionLevelStrict})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/protection/policy", bytes.NewReader(raw))
	handler.UpdateProtectionPolicy(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected policy update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	expected := config.ProtectionPolicyConfig{
		WebAttack:   config.ProtectionLevelStrict,
		APISecurity: config.ProtectionLevelHigh,
		BotCC:       config.ProtectionLevelLow,
		ThreatIntel: config.ProtectionLevelStrict,
	}
	if cfg.Protection.Policy != expected {
		t.Fatalf("partial update did not preserve existing policy: got %+v want %+v", cfg.Protection.Policy, expected)
	}
	if reloaded.Policy != expected {
		t.Fatalf("reload callback received wrong policy: got %+v want %+v", reloaded.Policy, expected)
	}
	if !strings.Contains(recorder.Body.String(), `"api_security":"high"`) ||
		!strings.Contains(recorder.Body.String(), `"bot_cc":"low"`) ||
		!strings.Contains(recorder.Body.String(), `"threat_intel":"strict"`) {
		t.Fatalf("response did not include preserved policy fields: %s", recorder.Body.String())
	}
}

func TestThreatIntelProviderTestUsesSavedSecretByProviderID(t *testing.T) {
	var gotAPIKey string
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-API-Key")
		_, _ = w.Write([]byte("203.0.113.77\n"))
	}))
	t.Cleanup(providerServer.Close)
	withThreatIntelHTTPClient(t, providerServer.Client())
	withThreatIntelProviderURLValidator(t, url.Parse)

	cfg := config.Default()
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:       "saved",
		Name:     "Saved Feed",
		Type:     "generic",
		Endpoint: providerServer.URL,
		APIKey:   "saved-provider-key",
		AuthType: "header",
		Format:   "cidr",
		Action:   "log",
		Enabled:  true,
	}}
	handler := New(Options{Config: &cfg})

	raw, _ := json.Marshal(map[string]any{"provider_id": "saved", "api_key": ""})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/test", bytes.NewReader(raw))
	handler.TestThreatIntelProvider(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected provider test ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if gotAPIKey != "saved-provider-key" {
		t.Fatalf("expected saved API key to be reused, got %q", gotAPIKey)
	}
	if !strings.Contains(recorder.Body.String(), `"count":1`) {
		t.Fatalf("expected parsed count in response, body=%s", recorder.Body.String())
	}
}

func TestImportThreatIntelNotifiesProtectionReload(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var reloaded config.ProtectionConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			reloaded = next
			return nil
		},
	})
	body := map[string]any{
		"format":   "csv",
		"source":   "feed-a",
		"contents": "ip,severity,action,confidence\n203.0.113.10,high,challenge,90\n",
	}
	raw, _ := json.Marshal(body)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/import", bytes.NewReader(raw))
	handler.ImportThreatIntel(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected import ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(reloaded.IP.ThreatIntel) != 1 {
		t.Fatalf("expected protection reload with imported intel, got %+v", reloaded.IP.ThreatIntel)
	}
	if reloaded.IP.ThreatIntel[0].Confidence != 0.9 || reloaded.IP.ThreatIntel[0].Action != "challenge" {
		t.Fatalf("unexpected imported intel: %+v", reloaded.IP.ThreatIntel[0])
	}
}

func TestSyncThreatIntelAllowsEmptyOptionalBody(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/sync", nil)
	handler.SyncThreatIntel(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected empty optional body to be accepted, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestSyncThreatIntelRejectsTrailingJSONDocument(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/sync", strings.NewReader(`{"provider_id":"demo"} {}`))
	handler.SyncThreatIntel(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected trailing JSON to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "exactly one JSON document") {
		t.Fatalf("expected explicit trailing JSON error, body=%s", recorder.Body.String())
	}
}

func TestUpdateIPAccessRulesNotifiesProtectionReload(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var reloaded config.ProtectionConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			reloaded = next
			return nil
		},
	})
	body := []config.IPAccessRuleConfig{{
		ID:         "allow-admin",
		Name:       "Allow office IP",
		Action:     "allow",
		Scope:      "path",
		SiteID:     "default",
		PathPrefix: "/admin",
		Entries:    []string{"203.0.113.10"},
		Enabled:    true,
	}}
	raw, _ := json.Marshal(body)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/ip/access-rules", bytes.NewReader(raw))
	handler.UpdateIPAccessRules(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected access rule update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(reloaded.IP.AccessRules) != 1 || reloaded.IP.AccessRules[0].ID != "allow-admin" {
		t.Fatalf("expected protection reload with access rules, got %+v", reloaded.IP.AccessRules)
	}
}

func TestApplyProviderAuthSupportsConfiguredAuthTypes(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		provider config.ThreatIntelProviderConfig
		verify   func(t *testing.T, request *http.Request)
	}{
		{
			name:     "default bearer",
			endpoint: "https://intel.example.test/feed",
			provider: config.ThreatIntelProviderConfig{
				APIKey: "bearer-key",
			},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				if got := request.Header.Get("Authorization"); got != "Bearer bearer-key" {
					t.Fatalf("expected bearer authorization, got %q", got)
				}
			},
		},
		{
			name:     "header token keeps explicit provider header",
			endpoint: "https://intel.example.test/feed",
			provider: config.ThreatIntelProviderConfig{
				APIKey:   "provider-key",
				AuthType: "header",
				Headers:  map[string]string{"X-API-Key": "header-key"},
			},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				if got := request.Header.Get("X-API-Key"); got != "header-key" {
					t.Fatalf("expected explicit X-API-Key to win, got %q", got)
				}
			},
		},
		{
			name:     "query token keeps existing query value",
			endpoint: "https://intel.example.test/feed?api_key=existing&resource=203.0.113.9",
			provider: config.ThreatIntelProviderConfig{
				APIKey:   "query-key",
				AuthType: "query",
			},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				query := request.URL.Query()
				if got := query.Get("api_key"); got != "existing" {
					t.Fatalf("expected existing api_key to win, got %q", got)
				}
				if got := query.Get("resource"); got != "203.0.113.9" {
					t.Fatalf("expected existing resource query to remain, got %q", got)
				}
			},
		},
		{
			name:     "basic auth",
			endpoint: "https://intel.example.test/feed",
			provider: config.ThreatIntelProviderConfig{
				APIKey:   "user:pass",
				AuthType: "basic",
			},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				user, pass, ok := request.BasicAuth()
				if !ok || user != "user" || pass != "pass" {
					t.Fatalf("expected basic auth user/pass, got ok=%v user=%q pass=%q", ok, user, pass)
				}
			},
		},
		{
			name:     "none only applies custom headers",
			endpoint: "https://intel.example.test/feed",
			provider: config.ThreatIntelProviderConfig{
				APIKey:   "unused-key",
				AuthType: "none",
				Headers:  map[string]string{"X-Feed-Version": "2026-06"},
			},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				if got := request.Header.Get("Authorization"); got != "" {
					t.Fatalf("expected no authorization header, got %q", got)
				}
				if got := request.Header.Get("X-API-Key"); got != "" {
					t.Fatalf("expected no api key header, got %q", got)
				}
				if got := request.Header.Get("X-Feed-Version"); got != "2026-06" {
					t.Fatalf("expected custom header, got %q", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.endpoint, nil)
			applyProviderAuth(request, tt.provider)
			tt.verify(t, request)
		})
	}
}

func TestProviderLookupURLBuildsKnownProviderQueries(t *testing.T) {
	tests := []struct {
		name       string
		provider   config.ThreatIntelProviderConfig
		ip         string
		wantHost   string
		wantPath   string
		wantQuery  map[string]string
		wantPrefix string
	}{
		{
			name: "abuseipdb default check endpoint",
			provider: config.ThreatIntelProviderConfig{
				Type: "abuseipdb",
			},
			ip:       "203.0.113.60",
			wantHost: "api.abuseipdb.com",
			wantPath: "/api/v2/check",
			wantQuery: map[string]string{
				"ipAddress":    "203.0.113.60",
				"maxAgeInDays": "90",
			},
		},
		{
			name: "otx ipv4 general endpoint",
			provider: config.ThreatIntelProviderConfig{
				Type: "otx",
			},
			ip:       "203.0.113.62",
			wantHost: "otx.alienvault.com",
			wantPath: "/api/v1/indicators/IPv4/203.0.113.62/general",
		},
		{
			name: "otx ipv6 general endpoint",
			provider: config.ThreatIntelProviderConfig{
				Type: "otx",
			},
			ip:       "2001:db8::1",
			wantHost: "otx.alienvault.com",
			wantPath: "/api/v1/indicators/IPv6/2001:db8::1/general",
		},
		{
			name: "threatbook keeps resource and apikey query",
			provider: config.ThreatIntelProviderConfig{
				Type:   "threatbook-intl",
				APIKey: "unit-key",
			},
			ip:       "203.0.113.44",
			wantHost: "api.threatbook.io",
			wantPath: "/v2/ip/query",
			wantQuery: map[string]string{
				"apikey":   "unit-key",
				"resource": "203.0.113.44",
			},
		},
		{
			name: "custom endpoint can use ip path template",
			provider: config.ThreatIntelProviderConfig{
				Type:     "generic",
				Endpoint: "https://intel.example.test/feed/{ip}.json",
			},
			ip:       "203.0.113.70",
			wantHost: "intel.example.test",
			wantPath: "/feed/203.0.113.70.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := providerLookupURL(tt.provider, tt.ip)
			if err != nil {
				t.Fatalf("providerLookupURL returned error: %v", err)
			}
			if got.Host != tt.wantHost {
				t.Fatalf("host mismatch: got %q want %q", got.Host, tt.wantHost)
			}
			if got.Path != tt.wantPath {
				t.Fatalf("path mismatch: got %q want %q", got.Path, tt.wantPath)
			}
			query := got.Query()
			for key, value := range tt.wantQuery {
				if actual := query.Get(key); actual != value {
					t.Fatalf("query %s mismatch: got %q want %q; raw=%s", key, actual, value, got.RawQuery)
				}
			}
		})
	}
}

func TestApplyProviderAuthUsesVendorHeaders(t *testing.T) {
	tests := []struct {
		name     string
		provider config.ThreatIntelProviderConfig
		verify   func(t *testing.T, request *http.Request)
	}{
		{
			name:     "abuseipdb key header",
			provider: config.ThreatIntelProviderConfig{Type: "abuseipdb", APIKey: "abuse-key"},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				if got := request.Header.Get("Key"); got != "abuse-key" {
					t.Fatalf("expected AbuseIPDB Key header, got %q", got)
				}
				if got := request.Header.Get("Accept"); got != "application/json" {
					t.Fatalf("expected JSON accept header, got %q", got)
				}
			},
		},
		{
			name:     "otx api key header",
			provider: config.ThreatIntelProviderConfig{Type: "otx", APIKey: "otx-key"},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				if got := request.Header.Get("X-OTX-API-KEY"); got != "otx-key" {
					t.Fatalf("expected OTX API key header, got %q", got)
				}
			},
		},
		{
			name:     "misp authorization header",
			provider: config.ThreatIntelProviderConfig{Type: "misp", APIKey: "misp-key"},
			verify: func(t *testing.T, request *http.Request) {
				t.Helper()
				if got := request.Header.Get("Authorization"); got != "misp-key" {
					t.Fatalf("expected MISP Authorization header, got %q", got)
				}
				if got := request.Header.Get("Accept"); got != "application/json" {
					t.Fatalf("expected JSON accept header, got %q", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://intel.example.test/feed", nil)
			applyProviderAuth(request, tt.provider)
			tt.verify(t, request)
		})
	}
}

func TestLookupThreatIntelDoesNotImportCleanProviderResult(t *testing.T) {
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "203.0.113.45" {
			t.Fatalf("expected threatbook resource query, got %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("apikey") != "unit-key" {
			t.Fatalf("expected threatbook apikey query, got %q", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"response_code":0,"data":{"203.0.113.45":{"judgments":[],"intelligences":{},"verdict":"clean"}}}`))
	}))
	t.Cleanup(providerServer.Close)
	withThreatIntelHTTPClient(t, providerServer.Client())
	withThreatIntelProviderURLValidator(t, url.Parse)

	cfg := config.Default()
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:       "tb",
		Name:     "ThreatBook",
		Type:     "threatbook",
		Endpoint: providerServer.URL,
		APIKey:   "unit-key",
		Format:   "threatbook",
		Action:   "challenge",
		Enabled:  true,
	}}
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	reloadCalled := false
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			reloadCalled = true
			return nil
		},
	})
	raw, _ := json.Marshal(map[string]any{"provider_id": "tb", "ip": "203.0.113.45"})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/lookup", bytes.NewReader(raw))
	handler.LookupThreatIntel(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected lookup ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			Imported int                        `json:"imported"`
			Items    []config.ThreatIntelConfig `json:"items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode lookup response: %v", err)
	}
	if response.Data.Imported != 0 || len(response.Data.Items) != 0 {
		t.Fatalf("clean lookup must not import indicators, got %+v", response.Data)
	}
	if reloadCalled || len(cfg.Protection.IP.ThreatIntel) != 0 {
		t.Fatalf("clean lookup should not persist or reload, reload=%v intel=%+v", reloadCalled, cfg.Protection.IP.ThreatIntel)
	}
}

func TestLookupThreatIntelImportsProviderConfirmedIndicator(t *testing.T) {
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response_code":0,"data":{"203.0.113.46":{"judgments":["Scanner"],"intelligences":{"threatbook_lab":[{"source":"ThreatBook Labs","confidence":91,"intel_types":["Scanner"]}]}}}}`))
	}))
	t.Cleanup(providerServer.Close)
	withThreatIntelHTTPClient(t, providerServer.Client())
	withThreatIntelProviderURLValidator(t, url.Parse)

	cfg := config.Default()
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:       "tb",
		Name:     "ThreatBook",
		Type:     "threatbook",
		Endpoint: providerServer.URL,
		Format:   "threatbook",
		Action:   "challenge",
		Enabled:  true,
	}}
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var reloaded config.ProtectionConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			reloaded = next
			return nil
		},
	})
	raw, _ := json.Marshal(map[string]any{"provider_id": "tb", "ip": "203.0.113.46"})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/lookup", bytes.NewReader(raw))
	handler.LookupThreatIntel(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected lookup ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(reloaded.IP.ThreatIntel) != 1 {
		t.Fatalf("expected one imported indicator, got %+v", reloaded.IP.ThreatIntel)
	}
	item := reloaded.IP.ThreatIntel[0]
	if item.Value != "203.0.113.46" || item.Source != "ThreatBook Labs" || item.Confidence != 0.91 {
		t.Fatalf("unexpected imported indicator: %+v", item)
	}
}

func TestThreatIntelProviderRejectsUnsafeEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "loopback",
			endpoint: "http://127.0.0.1/feed.json",
			want:     "provider host IP must be public",
		},
		{
			name:     "aws metadata",
			endpoint: "http://169.254.169.254/latest/meta-data",
			want:     "provider host IP must be public",
		},
		{
			name:     "aliyun metadata",
			endpoint: "http://100.100.100.200/latest/meta-data",
			want:     "provider host IP must be public",
		},
		{
			name:     "url credentials",
			endpoint: "https://user:pass@intel.example.test/feed",
			want:     "credentials in provider URL are not allowed",
		},
		{
			name:     "unsupported scheme",
			endpoint: "file:///etc/passwd",
			want:     "only http and https provider URLs are allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchProvider(context.Background(), config.ThreatIntelProviderConfig{
				Endpoint: tt.endpoint,
				Format:   "json",
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestReadLimitedResponseBodyRejectsOversizedBody(t *testing.T) {
	_, err := readLimitedResponseBody(strings.NewReader("12345"), 4, "provider response")
	if err == nil || !strings.Contains(err.Error(), "provider response exceeds 4 bytes") {
		t.Fatalf("expected oversized response error, got %v", err)
	}
}

func TestThreatIntelProviderRejectsLookupEndpointResolvedToPrivateIP(t *testing.T) {
	withThreatIntelResolver(t, func(ctx context.Context, network, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.8")}, nil
	})
	_, err := lookupProviderIP(context.Background(), config.ThreatIntelProviderConfig{
		Type:     "generic",
		Endpoint: "https://intel.example.test/lookup/{ip}.json",
		Format:   "json",
	}, "203.0.113.88")
	if err == nil || !strings.Contains(err.Error(), "provider host resolved to non-public IP") {
		t.Fatalf("expected DNS rebinding guard error, got %v", err)
	}
}

func withThreatIntelHTTPClient(t *testing.T, client *http.Client) {
	t.Helper()
	previous := threatIntelHTTPClient
	threatIntelHTTPClient = client
	t.Cleanup(func() {
		threatIntelHTTPClient = previous
	})
}

func withThreatIntelResolver(t *testing.T, resolver func(context.Context, string, string) ([]net.IP, error)) {
	t.Helper()
	previous := threatIntelResolveIP
	threatIntelResolveIP = resolver
	t.Cleanup(func() {
		threatIntelResolveIP = previous
	})
}

func withThreatIntelProviderURLValidator(t *testing.T, validator func(string) (*url.URL, error)) {
	t.Helper()
	previous := threatIntelProviderURLValidator
	threatIntelProviderURLValidator = validator
	t.Cleanup(func() {
		threatIntelProviderURLValidator = previous
	})
}
