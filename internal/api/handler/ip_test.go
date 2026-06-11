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
