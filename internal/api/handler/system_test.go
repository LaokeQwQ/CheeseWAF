package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
)

func TestUpdateSystemNotifiesAPISecReload(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var calls int
	var reloaded config.APISecConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnAPISecChanged: func(next config.APISecConfig) error {
			calls++
			reloaded = next
			return nil
		},
	})

	nextAPISec := cfg.APISec
	nextAPISec.Enabled = true
	nextAPISec.Validation.Enabled = true
	nextAPISec.Validation.Schemas = []config.APIEndpointSchemaConfig{{
		ID: "search", Method: http.MethodGet, PathPattern: "^/api/search$", RequiredParams: []string{"q"}, Enabled: true,
	}}
	nextAPISec.RateLimits = []config.APIEndpointLimitConfig{{
		ID: "search-rate", Method: http.MethodGet, PathPattern: "^/api/search$", Requests: 2, Window: time.Minute, Enabled: true,
	}}
	raw, _ := json.Marshal(map[string]any{"apisec": nextAPISec})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected system update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected one API security reload callback, got %d", calls)
	}
	if !reloaded.Enabled || len(reloaded.Validation.Schemas) != 1 || len(reloaded.RateLimits) != 1 {
		t.Fatalf("unexpected APISec reload payload: %+v", reloaded)
	}
	if cfg.APISec.Validation.Schemas[0].ID != "search" || cfg.APISec.RateLimits[0].ID != "search-rate" {
		t.Fatalf("system config was not updated: %+v", cfg.APISec)
	}
}

func TestUpdateSystemAppliesAndPersistsTimeSync(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var applied []config.TimeSyncConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnTimeSyncChanged: func(next config.TimeSyncConfig) error {
			applied = append(applied, next)
			return nil
		},
	})
	next := cfg.TimeSync
	next.SyncInterval = 45 * time.Minute
	raw, _ := json.Marshal(map[string]any{"time_sync": next})
	recorder := httptest.NewRecorder()
	handler.UpdateSystem(recorder, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected update success, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(applied) != 1 || applied[0].SyncInterval != 45*time.Minute {
		t.Fatalf("unexpected runtime apply calls: %+v", applied)
	}
	if cfg.TimeSync.SyncInterval != 45*time.Minute || !strings.Contains(recorder.Body.String(), `"time_sync"`) {
		t.Fatalf("time sync config not returned or updated: %+v body=%s", cfg.TimeSync, recorder.Body.String())
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.TimeSync.SyncInterval != 45*time.Minute {
		t.Fatalf("time sync config not persisted: %+v", loaded.TimeSync)
	}
}

func TestUpdateSystemMergesPartialTimeSyncWithoutDisabling(t *testing.T) {
	cfg := config.Default()
	previous := cfg.TimeSync
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var applied []config.TimeSyncConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnTimeSyncChanged: func(next config.TimeSyncConfig) error {
			applied = append(applied, next)
			return nil
		},
	})
	raw, _ := json.Marshal(map[string]any{"time_sync": map[string]any{"sync_interval": int64(45 * time.Minute)}})
	recorder := httptest.NewRecorder()
	handler.UpdateSystem(recorder, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected partial update success, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !cfg.TimeSync.Enabled || cfg.TimeSync.SyncInterval != 45*time.Minute {
		t.Fatalf("partial update corrupted time sync: %+v", cfg.TimeSync)
	}
	if len(cfg.TimeSync.Sources) != len(previous.Sources) || cfg.TimeSync.SelectionInterval != previous.SelectionInterval {
		t.Fatalf("partial update dropped unrelated fields: %+v", cfg.TimeSync)
	}
	if len(applied) != 1 || !applied[0].Enabled || applied[0].SyncInterval != 45*time.Minute {
		t.Fatalf("runtime apply missing merge: %+v", applied)
	}
}

func TestUpdateSystemRollsBackTimeSyncWhenRuntimeRejectsCandidate(t *testing.T) {
	cfg := config.Default()
	previous := cfg.TimeSync
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var intervals []time.Duration
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnTimeSyncChanged: func(next config.TimeSyncConfig) error {
			intervals = append(intervals, next.SyncInterval)
			if next.SyncInterval != previous.SyncInterval {
				return errors.New("time synchronization runtime rejected candidate")
			}
			return nil
		},
	})
	next := previous
	next.SyncInterval = 45 * time.Minute
	raw, _ := json.Marshal(map[string]any{"time_sync": next})
	recorder := httptest.NewRecorder()
	handler.UpdateSystem(recorder, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw)))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected runtime failure, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(intervals) != 2 || intervals[0] != next.SyncInterval || intervals[1] != previous.SyncInterval {
		t.Fatalf("expected candidate then previous runtime apply, got %v", intervals)
	}
	if cfg.TimeSync.SyncInterval != previous.SyncInterval {
		t.Fatalf("memory config changed after rejected runtime: %+v", cfg.TimeSync)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.TimeSync.SyncInterval != previous.SyncInterval {
		t.Fatalf("disk config changed after rejected runtime: %+v", loaded.TimeSync)
	}
}

func TestUpdateSystemRollsBackMemoryDiskAndRuntimeOnReloadFailure(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	previous := cfg.APISec
	var applied []bool
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnAPISecChanged: func(next config.APISecConfig) error {
			applied = append(applied, next.Enabled)
			if next.Enabled != previous.Enabled {
				return errors.New("reload failed")
			}
			return nil
		},
	})
	next := previous
	next.Enabled = !previous.Enabled
	raw, _ := json.Marshal(map[string]any{"apisec": next})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected reload failure, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.APISec.Enabled != previous.Enabled {
		t.Fatalf("memory config was not rolled back: %+v", cfg.APISec)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.APISec.Enabled != previous.Enabled {
		t.Fatalf("disk config changed after failed reload: %+v", loaded.APISec)
	}
	if len(applied) != 2 || applied[0] != next.Enabled || applied[1] != previous.Enabled {
		t.Fatalf("expected candidate apply followed by old runtime restore, got %v", applied)
	}
}

func TestUpdateSystemFreezesWritesWhenRuntimeRollbackFails(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnAPISecChanged: func(config.APISecConfig) error {
			return errors.New("runtime unavailable")
		},
	})
	next := cfg.APISec
	next.Enabled = !next.Enabled
	raw, _ := json.Marshal(map[string]any{"apisec": next})
	recorder := httptest.NewRecorder()
	handler.UpdateSystem(recorder, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw)))
	if recorder.Code != http.StatusInternalServerError || !handler.configWriteFrozen {
		t.Fatalf("expected failed rollback to freeze writes, code=%d body=%s frozen=%v", recorder.Code, recorder.Body.String(), handler.configWriteFrozen)
	}

	recorder = httptest.NewRecorder()
	handler.UpdateSystem(recorder, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader([]byte(`{"logging":{"level":"debug"}}`))))
	if recorder.Code != http.StatusLocked || !strings.Contains(recorder.Body.String(), "CONFIG_WRITES_FROZEN") {
		t.Fatalf("expected subsequent write rejection, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestUpdateSystemDoesNotReloadSitesForUnrelatedConfig(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var siteReloads int
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnSitesChanged: func([]config.SiteConfig) error {
			siteReloads++
			return nil
		},
	})
	nextLogging := cfg.Logging
	nextLogging.Level = "debug"
	raw, _ := json.Marshal(map[string]any{"logging": nextLogging})
	recorder := httptest.NewRecorder()
	handler.UpdateSystem(recorder, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected update success, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if siteReloads != 0 {
		t.Fatalf("unrelated logging update reloaded sites %d times", siteReloads)
	}
}

func TestPersistConfigRestoresPreviousFileWhenVersionWriteFails(t *testing.T) {
	cfg := config.Default()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "versions"), []byte("not-a-directory"), 0o600); err != nil {
		t.Fatalf("block primary versions directory: %v", err)
	}
	runtimeBlocker := filepath.Join(dir, "runtime-file")
	if err := os.WriteFile(runtimeBlocker, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatalf("block fallback runtime directory: %v", err)
	}
	cfg.Setup.RuntimeDir = runtimeBlocker
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	_, err := handler.commitConfigMutation(func(candidate *config.Config) error {
		candidate.Logging.Level = "debug"
		return nil
	}, nil)
	if err == nil {
		t.Fatal("expected version write failure")
	}
	loaded, loadErr := config.Load(configPath)
	if loadErr != nil {
		t.Fatalf("load restored config: %v", loadErr)
	}
	if loaded.Logging.Level == "debug" {
		t.Fatalf("new config remained after version failure: %+v", loaded.Logging)
	}
}

func TestConfigMutationsMergeConcurrentIndependentUpdates(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})
	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		<-start
		_, err := handler.commitConfigMutation(func(candidate *config.Config) error {
			candidate.Logging.Level = "debug"
			return nil
		}, nil)
		errs <- err
	}()
	go func() {
		<-start
		_, err := handler.commitConfigMutation(func(candidate *config.Config) error {
			candidate.AI.Model = "transaction-test-model"
			return nil
		}, nil)
		errs <- err
	}()
	close(start)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent mutation failed: %v", err)
		}
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Logging.Level != "debug" || loaded.AI.Model != "transaction-test-model" {
		t.Fatalf("independent update was lost: logging=%q model=%q", loaded.Logging.Level, loaded.AI.Model)
	}
}

func TestUpdateSystemPersistsConsoleSecurityEntry(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	nextConsole := cfg.Console
	nextConsole.Login.SecurityEntry.Enabled = true
	nextConsole.Login.SecurityEntry.Path = "/ops-door"
	nextConsole.Login.SecurityEntry.CookieName = "cw_ops_entry"
	raw, _ := json.Marshal(map[string]any{"console": nextConsole})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected system update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !cfg.Console.Login.SecurityEntry.Enabled || cfg.Console.Login.SecurityEntry.Path != "/ops-door" || cfg.Console.Login.SecurityEntry.CookieName != "cw_ops_entry" {
		t.Fatalf("security entry was not updated in memory: %+v", cfg.Console.Login.SecurityEntry)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !loaded.Console.Login.SecurityEntry.Enabled || loaded.Console.Login.SecurityEntry.Path != "/ops-door" || loaded.Console.Login.SecurityEntry.CookieName != "cw_ops_entry" {
		t.Fatalf("security entry was not persisted: %+v", loaded.Console.Login.SecurityEntry)
	}
}

func TestSystemRedactsSensitiveConfigValues(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.ClickHouse.Password = "clickhouse-secret"
	cfg.Storage.PostgreSQL.DSN = "postgres://user:postgres-secret@example.test/db"
	cfg.Storage.Elasticsearch.Password = "elastic-secret"
	cfg.Storage.Elasticsearch.APIKey = "elastic-api-secret"
	cfg.Storage.Elasticsearch.Headers = map[string]string{"Authorization": "Bearer elastic-header-secret"}
	cfg.ACME.DNSProviders = []config.ACMEDNSProviderConfig{{
		ID:      "cf",
		Name:    "Cloudflare",
		API:     "dns_cf",
		Env:     map[string]string{"CF_TOKEN": "cf-secret"},
		Enabled: true,
	}}
	cfg.Protection.Bot.Secret = "strong-bot-secret-for-redaction"
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:      "otx",
		Name:    "OTX",
		APIKey:  "otx-secret",
		Headers: map[string]string{"X-OTX-API-KEY": "otx-header-secret"},
		Enabled: true,
	}}
	cfg.Monitor.Notifiers = []config.NotifierConfig{{
		ID:      "webhook",
		Name:    "Webhook",
		Type:    "webhook",
		Token:   "notify-secret",
		Headers: map[string]string{"Authorization": "Bearer notify-header-secret"},
		Enabled: true,
	}}
	cfg.APISec.Auth.JWTSharedSecret = "jwt-secret"
	cfg.APISec.Auth.JWTPublicKeyPEM = "public-key-pem-secret"
	cfg.APISec.Auth.JWKSJSON = `{"keys":["jwks-secret"]}`
	cfg.AI.Enabled = true
	cfg.AI.APIKey = "legacy-ai-secret"
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://api.example.test/v1"
	cfg.AI.Model = "gpt-test"
	cfg.AI.Assistant.APIKey = "assistant-ai-secret"
	cfg.AI.Assistant.Provider = "openai"
	cfg.AI.Assistant.APIBase = "https://api.example.test/v1"
	cfg.AI.Assistant.Model = "gpt-test"
	cfg.AI.Reasoning.APIKey = "reasoning-ai-secret"
	cfg.AI.Reasoning.Provider = "openai"
	cfg.AI.Reasoning.APIBase = "https://api.example.test/v1"
	cfg.AI.Reasoning.Model = "gpt-reason"
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	handler.System(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected system response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, secret := range []string{
		"clickhouse-secret",
		"postgres-secret",
		"elastic-secret",
		"elastic-api-secret",
		"elastic-header-secret",
		"cf-secret",
		"strong-bot-secret-for-redaction",
		"otx-secret",
		"otx-header-secret",
		"notify-secret",
		"notify-header-secret",
		"jwt-secret",
		"public-key-pem-secret",
		"jwks-secret",
		"legacy-ai-secret",
		"assistant-ai-secret",
		"reasoning-ai-secret",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("system response leaked secret %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"api_key_set":true`) {
		t.Fatalf("system response should preserve AI key presence status, body=%s", body)
	}
	if !strings.Contains(body, `"env_keys":["CF_TOKEN"]`) || !strings.Contains(body, `"env_set":true`) {
		t.Fatalf("system response should expose ACME env presence without values, body=%s", body)
	}
}

func TestUpdateSystemPreservesRedactedSecretsOnEmptyPayload(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.ClickHouse.Password = "old-clickhouse-secret"
	cfg.Storage.PostgreSQL.DSN = "postgres://user:old-postgres-secret@example.test/db"
	cfg.Storage.Elasticsearch.Password = "old-elastic-secret"
	cfg.Storage.Elasticsearch.APIKey = "old-elastic-api-secret"
	cfg.Storage.Elasticsearch.Headers = map[string]string{"Authorization": "Bearer old-elastic-header-secret"}
	cfg.ACME.DNSProviders = []config.ACMEDNSProviderConfig{{
		ID:      "cf",
		Name:    "Cloudflare",
		API:     "dns_cf",
		Env:     map[string]string{"CF_TOKEN": "old-cf-secret"},
		Enabled: true,
	}}
	cfg.Protection.Bot.Secret = "old-strong-bot-secret"
	cfg.Protection.IP.Providers = []config.ThreatIntelProviderConfig{{
		ID:      "otx",
		Name:    "OTX",
		APIKey:  "old-otx-secret",
		Headers: map[string]string{"X-OTX-API-KEY": "old-otx-header-secret"},
		Enabled: true,
	}}
	cfg.Monitor.Notifiers = []config.NotifierConfig{{
		ID:      "webhook",
		Name:    "Webhook",
		Type:    "webhook",
		Token:   "old-notify-secret",
		Headers: map[string]string{"Authorization": "Bearer old-notify-header-secret"},
		Enabled: true,
	}}
	cfg.APISec.Auth.JWTSharedSecret = "old-jwt-secret"
	cfg.APISec.Auth.JWTPublicKeyPEM = "old-public-key-pem"
	cfg.APISec.Auth.JWKSJSON = `{"keys":["old-jwks-secret"]}`
	cfg.AI.APIKey = "old-ai-secret"
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	nextStorage := cfg.Storage
	nextStorage.ClickHouse.Password = ""
	nextStorage.PostgreSQL.DSN = ""
	nextStorage.Elasticsearch.Password = ""
	nextStorage.Elasticsearch.APIKey = ""
	nextStorage.Elasticsearch.Headers = map[string]string{"Authorization": ""}
	nextACME := cfg.ACME
	nextACME.DNSProviders = append([]config.ACMEDNSProviderConfig(nil), cfg.ACME.DNSProviders...)
	nextACME.DNSProviders[0].Env = map[string]string{"CF_TOKEN": ""}
	nextProtection := cfg.Protection
	nextProtection.Bot.Secret = ""
	nextProtection.IP.Providers = append([]config.ThreatIntelProviderConfig(nil), cfg.Protection.IP.Providers...)
	nextProtection.IP.Providers[0].APIKey = ""
	nextProtection.IP.Providers[0].Headers = map[string]string{"X-OTX-API-KEY": ""}
	nextMonitor := cfg.Monitor
	nextMonitor.Notifiers = append([]config.NotifierConfig(nil), cfg.Monitor.Notifiers...)
	nextMonitor.Notifiers[0].Token = ""
	nextMonitor.Notifiers[0].Headers = map[string]string{"Authorization": ""}
	nextAPISec := cfg.APISec
	nextAPISec.Auth.JWTSharedSecret = ""
	nextAPISec.Auth.JWTPublicKeyPEM = ""
	nextAPISec.Auth.JWKSJSON = ""
	nextAI := cfg.AI
	nextAI.APIKey = ""
	raw, _ := json.Marshal(map[string]any{
		"storage":    nextStorage,
		"acme":       nextACME,
		"protection": nextProtection,
		"monitor":    nextMonitor,
		"apisec":     nextAPISec,
		"ai":         nextAI,
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected system update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if cfg.Storage.ClickHouse.Password != "old-clickhouse-secret" ||
		cfg.Storage.PostgreSQL.DSN != "postgres://user:old-postgres-secret@example.test/db" ||
		cfg.Storage.Elasticsearch.Password != "old-elastic-secret" ||
		cfg.Storage.Elasticsearch.APIKey != "old-elastic-api-secret" ||
		cfg.Storage.Elasticsearch.Headers["Authorization"] != "Bearer old-elastic-header-secret" ||
		cfg.ACME.DNSProviders[0].Env["CF_TOKEN"] != "old-cf-secret" ||
		cfg.Protection.Bot.Secret != "old-strong-bot-secret" ||
		cfg.Protection.IP.Providers[0].APIKey != "old-otx-secret" ||
		cfg.Protection.IP.Providers[0].Headers["X-OTX-API-KEY"] != "old-otx-header-secret" ||
		cfg.Monitor.Notifiers[0].Token != "old-notify-secret" ||
		cfg.Monitor.Notifiers[0].Headers["Authorization"] != "Bearer old-notify-header-secret" ||
		cfg.APISec.Auth.JWTSharedSecret != "old-jwt-secret" ||
		cfg.APISec.Auth.JWTPublicKeyPEM != "old-public-key-pem" ||
		cfg.APISec.Auth.JWKSJSON != `{"keys":["old-jwks-secret"]}` ||
		cfg.AI.APIKey != "old-ai-secret" {
		t.Fatal("redacted empty update did not preserve one or more existing secret values")
	}
	body := recorder.Body.String()
	for _, secret := range []string{
		"old-clickhouse-secret",
		"old-postgres-secret",
		"old-elastic-secret",
		"old-cf-secret",
		"old-strong-bot-secret",
		"old-otx-secret",
		"old-notify-secret",
		"old-jwt-secret",
		"old-ai-secret",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("update response leaked preserved secret %q: %s", secret, body)
		}
	}
}

func TestUpdateSystemRejectsEnabledChinaBoundaryWithoutSourceProof(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	nextConsole := cfg.Console
	nextConsole.Map.ChinaBoundary.Enabled = true
	nextConsole.Map.ChinaBoundary.SourceType = "file"
	nextConsole.Map.ChinaBoundary.Source = "./data/maps/china-boundary.geojson"
	raw, _ := json.Marshal(map[string]any{"console": nextConsole})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(raw))
	handler.UpdateSystem(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unlicensed boundary, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(configFileContents(t, configPath), "china-boundary.geojson") {
		t.Fatalf("invalid boundary config was persisted")
	}
}

func configFileContents(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	return string(body)
}

func TestChinaMapBoundaryDisabled(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system/map/china-boundary", nil)
	handler.ChinaMapBoundary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected disabled boundary response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"enabled":false`) {
		t.Fatalf("expected enabled=false response, body=%s", recorder.Body.String())
	}
}

func TestChinaMapBoundaryReturnsValidFeatureCollection(t *testing.T) {
	cfg := config.Default()
	boundaryFile := filepath.Join(t.TempDir(), "china-boundary.geojson")
	if err := os.WriteFile(boundaryFile, []byte(`{"type":"FeatureCollection","features":[{"type":"Feature","properties":{"name":"coverage"},"geometry":{"type":"Point","coordinates":[116.4,39.9]}}]}`), 0o600); err != nil {
		t.Fatalf("write boundary fixture: %v", err)
	}
	cfg.Console.Map.ChinaBoundary = config.MapBoundaryConfig{
		Enabled:    true,
		SourceType: "file",
		Source:     boundaryFile,
		License:    "licensed test fixture",
		ReviewID:   "GS-test",
	}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system/map/china-boundary", nil)
	handler.ChinaMapBoundary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected valid boundary response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"enabled":true`) || !strings.Contains(recorder.Body.String(), `"FeatureCollection"`) {
		t.Fatalf("expected boundary payload, body=%s", recorder.Body.String())
	}
}

func TestChinaMapBoundaryRejectsNonFeatureCollection(t *testing.T) {
	cfg := config.Default()
	boundaryFile := filepath.Join(t.TempDir(), "china-boundary.geojson")
	if err := os.WriteFile(boundaryFile, []byte(`{"type":"Feature","properties":{},"geometry":{"type":"Point","coordinates":[116.4,39.9]}}`), 0o600); err != nil {
		t.Fatalf("write boundary fixture: %v", err)
	}
	cfg.Console.Map.ChinaBoundary = config.MapBoundaryConfig{
		Enabled:    true,
		SourceType: "file",
		Source:     boundaryFile,
		License:    "licensed test fixture",
		ReviewID:   "GS-test",
	}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system/map/china-boundary", nil)
	handler.ChinaMapBoundary(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid boundary rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "FeatureCollection") {
		t.Fatalf("expected FeatureCollection error, body=%s", recorder.Body.String())
	}
}

func TestChinaMapBoundaryRejectsPrivateRemoteSourceByDefault(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/geo+json")
		_, _ = w.Write([]byte(`{"type":"FeatureCollection","features":[{"type":"Feature","properties":{"name":"coverage"},"geometry":{"type":"Point","coordinates":[116.4,39.9]}}]}`))
	}))
	t.Cleanup(source.Close)

	cfg := config.Default()
	cfg.Console.Map.ChinaBoundary = config.MapBoundaryConfig{
		Enabled:       true,
		SourceType:    "url",
		Source:        source.URL,
		License:       "licensed test fixture",
		ReviewID:      "GS-test",
		AllowInsecure: true,
	}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system/map/china-boundary", nil)
	handler.ChinaMapBoundary(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected private remote boundary source rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "public") {
		t.Fatalf("expected public-host guard error, body=%s", recorder.Body.String())
	}
}

func TestChinaMapBoundaryAllowsExplicitPrivateRemoteSource(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/geo+json")
		_, _ = w.Write([]byte(`{"type":"FeatureCollection","features":[{"type":"Feature","properties":{"name":"coverage"},"geometry":{"type":"Point","coordinates":[116.4,39.9]}}]}`))
	}))
	t.Cleanup(source.Close)

	cfg := config.Default()
	cfg.Console.Map.ChinaBoundary = config.MapBoundaryConfig{
		Enabled:       true,
		SourceType:    "url",
		Source:        source.URL,
		License:       "licensed test fixture",
		ReviewID:      "GS-test",
		AllowInsecure: true,
		AllowPrivate:  true,
	}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/system/map/china-boundary", nil)
	handler.ChinaMapBoundary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected explicitly allowed private remote boundary source ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"enabled":true`) || !strings.Contains(recorder.Body.String(), `"FeatureCollection"`) {
		t.Fatalf("expected remote boundary payload, body=%s", recorder.Body.String())
	}
}

func TestStorageBackendTestRejectsPrivateHTTPEndpointByDefault(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("private storage endpoint should not receive test request by default")
	}))
	t.Cleanup(source.Close)

	storage := config.Default().Storage
	storage.ClickHouse.Enabled = true
	storage.ClickHouse.Endpoint = source.URL

	err := testStorage(context.Background(), "clickhouse", storage)
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("expected private endpoint guard error, got %v", err)
	}
}

func TestStorageBackendTestAllowsExplicitPrivateHTTPEndpoint(t *testing.T) {
	var gotAuth bool
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		gotAuth = ok && user == "cw" && password == "secret"
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(source.Close)

	storage := config.Default().Storage
	storage.ClickHouse.Enabled = true
	storage.ClickHouse.Endpoint = source.URL
	storage.ClickHouse.Username = "cw"
	storage.ClickHouse.Password = "secret"
	storage.ClickHouse.AllowPrivateEndpoint = true

	if err := testStorage(context.Background(), "clickhouse", storage); err != nil {
		t.Fatalf("expected explicitly allowed private endpoint to pass storage test: %v", err)
	}
	if !gotAuth {
		t.Fatal("expected storage test to preserve configured basic auth")
	}
}

func TestStorageBackendTestRejectsSQLitePathOutsideDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	storage := config.Default().Storage
	storage.SQLite.Path = filepath.Join(t.TempDir(), "outside.db")

	err := testStorageWithDataDir(context.Background(), "sqlite", storage, dataDir)
	if err == nil || !strings.Contains(err.Error(), "data directory") {
		t.Fatalf("expected sqlite path outside data dir to be rejected, got %v", err)
	}
}

func TestStorageBackendTestAllowsSQLitePathUnderDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	storage := config.Default().Storage
	storage.SQLite.Path = "nested/cheesewaf.db"

	if err := testStorageWithDataDir(context.Background(), "sqlite", storage, dataDir); err != nil {
		t.Fatalf("expected sqlite path under data dir to pass storage test: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "nested", "cheesewaf.db")); err != nil {
		t.Fatalf("expected sqlite test file under data dir: %v", err)
	}
}

func TestChinaMapBoundaryByCodeRejectsInvalidAdcode(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := requestWithAdcode(http.MethodGet, "/api/system/map/china-boundary/not-code", "not-code")
	handler.ChinaMapBoundaryByCode(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected bad adcode rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestChinaMapBoundaryByCodeDisabled(t *testing.T) {
	cfg := config.Default()
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := requestWithAdcode(http.MethodGet, "/api/system/map/china-boundary/330100", "330100")
	handler.ChinaMapBoundaryByCode(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected disabled boundary response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"enabled":false`) || !strings.Contains(body, `"adcode":"330100"`) {
		t.Fatalf("expected disabled adcode response, body=%s", body)
	}
}

func TestChinaMapBoundaryByCodeLoadsDirectoryCandidate(t *testing.T) {
	cfg := config.Default()
	boundaryDir := t.TempDir()
	boundaryFile := filepath.Join(boundaryDir, "330100.json")
	if err := os.WriteFile(boundaryFile, []byte(`{"type":"FeatureCollection","features":[{"type":"Feature","properties":{"name":"杭州市","adcode":"330100"},"geometry":{"type":"Point","coordinates":[120.2,30.3]}}]}`), 0o600); err != nil {
		t.Fatalf("write boundary fixture: %v", err)
	}
	cfg.Console.Map.ChinaBoundary = config.MapBoundaryConfig{
		Enabled:     true,
		SourceType:  "file",
		Source:      boundaryDir,
		License:     "licensed test fixture",
		ReviewID:    "GS-test",
		Attribution: "unit-test",
	}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := requestWithAdcode(http.MethodGet, "/api/system/map/china-boundary/330100", "330100")
	handler.ChinaMapBoundaryByCode(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected valid adcode boundary response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"enabled":true`) || !strings.Contains(body, `"adcode":"330100"`) || !strings.Contains(body, `"resolved_source"`) {
		t.Fatalf("expected adcode boundary payload, body=%s", body)
	}
}

func TestChinaMapBoundaryByCodeReportsMissingCandidate(t *testing.T) {
	cfg := config.Default()
	cfg.Console.Map.ChinaBoundary = config.MapBoundaryConfig{
		Enabled:    true,
		SourceType: "file",
		Source:     t.TempDir(),
		License:    "licensed test fixture",
		ReviewID:   "GS-test",
	}
	handler := New(Options{Config: &cfg})

	recorder := httptest.NewRecorder()
	request := requestWithAdcode(http.MethodGet, "/api/system/map/china-boundary/330100", "330100")
	handler.ChinaMapBoundaryByCode(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected missing adcode to be a soft disabled response, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"enabled":false`) || !strings.Contains(body, "330100") {
		t.Fatalf("expected missing boundary reason, body=%s", body)
	}
}

func requestWithAdcode(method, target, adcode string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("adcode", adcode)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func TestUpdateBlockPageConfigPersistsAndNotifies(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls int
	var reloaded config.BlockPageConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls++
			reloaded = next
			return nil
		},
	})
	payload := config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body>{{.TraceID}}</body></html>`,
	}
	raw, _ := json.Marshal(payload)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/block-pages/config", bytes.NewReader(raw))
	handler.UpdateBlockPageConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected block page update ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls != 1 || !reloaded.CustomEnabled {
		t.Fatalf("expected block page reload callback, calls=%d payload=%+v", calls, reloaded)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML == "" {
		t.Fatalf("block page config was not persisted: %+v", loaded.BlockPage)
	}
}

func TestPreviewBlockPageConfigRendersRuntimeHTMLWithoutPersisting(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls int
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls++
			return nil
		},
	})
	payload := config.BlockPageConfig{
		TemplateID:    "minimal",
		CustomEnabled: true,
		CustomHTML:    `<html><body><main>event={{.EventID}} status={{.Status}} type={{.AttackType}}</main></body></html>`,
	}
	raw, _ := json.Marshal(payload)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/block-pages/preview", bytes.NewReader(raw))
	request.RemoteAddr = "203.0.113.10:49152"

	handler.PreviewBlockPageConfig(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected preview ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data struct {
			HTML    string `json:"html"`
			EventID string `json:"event_id"`
			TraceID string `json:"trace_id"`
			Status  int    `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if body.Data.EventID == "" || body.Data.TraceID != body.Data.EventID {
		t.Fatalf("expected preview trace/event ids, got %+v", body.Data)
	}
	if body.Data.Status != http.StatusForbidden || !strings.Contains(body.Data.HTML, body.Data.EventID) || strings.Contains(body.Data.HTML, "{{.EventID}}") {
		t.Fatalf("preview did not render runtime data: %+v", body.Data)
	}
	if calls != 0 {
		t.Fatalf("preview must not trigger hot reload, calls=%d", calls)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if loaded.BlockPage.CustomEnabled {
		t.Fatalf("preview must not persist block page config: %+v", loaded.BlockPage)
	}
}

func TestUploadAndDeleteCustomBlockPagePersistsAndNotifies(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls []config.BlockPageConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls = append(calls, next)
			return nil
		},
	})

	customHTML := `<html><body><main data-event="{{.EventID}}">blocked {{.TraceID}}</main></body></html>`
	uploadRecorder := httptest.NewRecorder()
	uploadRequest := multipartBlockPageUploadRequest(t, customHTML, "custom-block.html", "minimal")
	handler.UploadBlockPageHTML(uploadRecorder, uploadRequest)
	if uploadRecorder.Code != http.StatusOK {
		t.Fatalf("expected upload ok, code=%d body=%s", uploadRecorder.Code, uploadRecorder.Body.String())
	}
	if len(calls) != 1 || !calls[0].CustomEnabled || calls[0].CustomHTML != customHTML {
		t.Fatalf("expected upload reload callback with custom html, calls=%+v", calls)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config after upload: %v", err)
	}
	if !loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != customHTML {
		t.Fatalf("uploaded block page was not persisted: %+v", loaded.BlockPage)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/block-pages/custom", nil)
	handler.DeleteCustomBlockPage(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("expected delete custom ok, code=%d body=%s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if len(calls) != 2 || calls[1].CustomEnabled || calls[1].CustomHTML != "" {
		t.Fatalf("expected delete reload callback to clear custom html, calls=%+v", calls)
	}
	loaded, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config after delete: %v", err)
	}
	if loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != "" {
		t.Fatalf("custom block page was not cleared from persisted config: %+v", loaded.BlockPage)
	}
}

func TestUploadCustomBlockPageRejectsNonHTMLUpload(t *testing.T) {
	cfg := config.Default()
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	handler := New(Options{Config: &cfg, ConfigPath: configPath})

	recorder := httptest.NewRecorder()
	request := multipartBlockPageUploadRequest(t, `not html`, "notes.txt", "minimal")
	handler.UploadBlockPageHTML(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "BLOCK_PAGE_UPLOAD_NOT_HTML") {
		t.Fatalf("expected non-html upload rejection, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != "" {
		t.Fatalf("non-html upload mutated config: %+v", loaded.BlockPage)
	}
}

func TestUploadCustomBlockPageRejectsInvalidTemplateWithoutMutatingConfig(t *testing.T) {
	cfg := config.Default()
	cfg.BlockPage.CustomEnabled = true
	cfg.BlockPage.CustomHTML = `<html><body>{{.TraceID}}</body></html>`
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var calls int
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnBlockPageChanged: func(next config.BlockPageConfig) error {
			calls++
			return nil
		},
	})

	recorder := httptest.NewRecorder()
	request := multipartBlockPageUploadRequest(t, `<html><body>{{if}}</body></html>`, "bad.html", "minimal")
	handler.UploadBlockPageHTML(recorder, request)
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "BLOCK_PAGE_TEMPLATE_INVALID") {
		t.Fatalf("expected invalid template rejection, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if calls != 0 {
		t.Fatalf("invalid upload should not notify hot reload, calls=%d", calls)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load saved config: %v", err)
	}
	if !loaded.BlockPage.CustomEnabled || loaded.BlockPage.CustomHTML != `<html><body>{{.TraceID}}</body></html>` {
		t.Fatalf("invalid upload mutated persisted config: %+v", loaded.BlockPage)
	}
}

func multipartBlockPageUploadRequest(t *testing.T, html, filename, templateID string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if templateID != "" {
		if err := writer.WriteField("template_id", templateID); err != nil {
			t.Fatalf("write template field: %v", err)
		}
	}
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create upload field: %v", err)
	}
	if _, err := part.Write([]byte(html)); err != nil {
		t.Fatalf("write upload body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/block-pages/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func TestWriteErrorIncludesTraceID(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeError(recorder, http.StatusBadRequest, "BAD_REQUEST", "bad")
	if recorder.Header().Get("X-CheeseWAF-Trace-ID") == "" {
		t.Fatal("expected trace id response header")
	}
	if recorder.Header().Get("X-CheeseWAF-Event-ID") == "" {
		t.Fatal("expected event id response header")
	}
	if recorder.Header().Get("X-CheeseWAF-Event-ID") != recorder.Header().Get("X-CheeseWAF-Trace-ID") {
		t.Fatalf("event id should match trace id header, event=%q trace=%q", recorder.Header().Get("X-CheeseWAF-Event-ID"), recorder.Header().Get("X-CheeseWAF-Trace-ID"))
	}
	var body struct {
		Error struct {
			TraceID string `json:"trace_id"`
			EventID string `json:"event_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if body.Error.TraceID == "" || body.Error.TraceID != recorder.Header().Get("X-CheeseWAF-Trace-ID") {
		t.Fatalf("trace id mismatch header=%q body=%q", recorder.Header().Get("X-CheeseWAF-Trace-ID"), body.Error.TraceID)
	}
	if body.Error.EventID == "" || body.Error.EventID != recorder.Header().Get("X-CheeseWAF-Event-ID") {
		t.Fatalf("event id mismatch header=%q body=%q", recorder.Header().Get("X-CheeseWAF-Event-ID"), body.Error.EventID)
	}
}
