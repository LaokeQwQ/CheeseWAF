package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

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
				"apikey":  "unit-key",
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
