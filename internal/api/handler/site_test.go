package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

func TestSiteMutationStoreFailuresDoNotReturnSuccess(t *testing.T) {
	tests := []string{"create", "update", "delete"}
	for _, operation := range tests {
		t.Run(operation, func(t *testing.T) {
			handler, store, site := newSiteTestHandler(t)
			failure := errors.New("site store unavailable")
			failingStore := &siteFailureStore{Store: store}
			handler.Store = failingStore

			router := chi.NewRouter()
			var request *http.Request
			switch operation {
			case "create":
				failingStore.createErr = failure
				payload := storage.Site{
					ID:         "site-create-failure",
					Name:       "site-create-failure",
					Domains:    []string{"create-failure.example.test"},
					Upstreams:  []string{"127.0.0.1:9100"},
					WAFEnabled: true,
					Enabled:    true,
				}
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatalf("marshal create payload: %v", err)
				}
				router.Post("/sites", handler.CreateSite)
				request = httptest.NewRequest(http.MethodPost, "/sites", bytes.NewReader(raw))
			case "update":
				failingStore.updateErr = failure
				payload := site
				payload.Name = "site-update-failure"
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatalf("marshal update payload: %v", err)
				}
				router.Put("/sites/{id}", handler.UpdateSite)
				request = httptest.NewRequest(http.MethodPut, "/sites/"+site.ID, bytes.NewReader(raw))
			case "delete":
				second := site
				second.ID = "site-delete-failure"
				second.Name = "site-delete-failure"
				second.Domains = []string{"delete-failure.example.test"}
				if err := store.CreateSite(context.Background(), &second); err != nil {
					t.Fatalf("create second site: %v", err)
				}
				failingStore.deleteErr = failure
				router.Delete("/sites/{id}", handler.DeleteSite)
				request = httptest.NewRequest(http.MethodDelete, "/sites/"+second.ID, nil)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			assertSiteAPIError(t, recorder, http.StatusInternalServerError, "STORE_ERROR")

			switch operation {
			case "create":
				stored, err := store.GetSite(context.Background(), "site-create-failure")
				if err != nil {
					t.Fatalf("read failed create: %v", err)
				}
				if stored != nil {
					t.Fatalf("failed create reached persistent store: %+v", stored)
				}
			case "update":
				stored, err := store.GetSite(context.Background(), site.ID)
				if err != nil {
					t.Fatalf("read failed update: %v", err)
				}
				if stored == nil || stored.Name != site.Name {
					t.Fatalf("failed update changed persistent store: %+v", stored)
				}
			case "delete":
				stored, err := store.GetSite(context.Background(), "site-delete-failure")
				if err != nil {
					t.Fatalf("read failed delete: %v", err)
				}
				if stored == nil {
					t.Fatal("failed delete removed site from persistent store")
				}
			}
		})
	}
}

func TestUpdateSitePersistsConsistentlyAcrossStoreAndConfigReload(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	payload := site
	payload.Name = "persisted-site"
	payload.Domains = []string{"persisted.example.test", "persisted-alt.example.test"}
	payload.Upstreams = []string{"127.0.0.1:9200", "127.0.0.1:9201"}
	payload.WAFMode = "monitor"
	payload.Advanced.Origin.ProxyTimeout = "47s"
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal update payload: %v", err)
	}

	router := chi.NewRouter()
	router.Put("/sites/{id}", handler.UpdateSite)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/sites/"+site.ID, bytes.NewReader(raw)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected site update success, code=%d body=%s", recorder.Code, recorder.Body.String())
	}

	stored, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("reload site from sqlite: %v", err)
	}
	if stored == nil {
		t.Fatal("updated site missing from sqlite")
	}
	loaded, err := config.Load(handler.ConfigPath)
	if err != nil {
		t.Fatalf("reload config from disk: %v", err)
	}
	if len(loaded.Sites) != 1 {
		t.Fatalf("reloaded config site count=%d, want 1", len(loaded.Sites))
	}
	loadedSite := loaded.Sites[0]
	if stored.Name != payload.Name || loadedSite.Name != payload.Name || handler.Config.Sites[0].Name != payload.Name {
		t.Fatalf("site name diverged after reload: sqlite=%q yaml=%q memory=%q", stored.Name, loadedSite.Name, handler.Config.Sites[0].Name)
	}
	if strings.Join(stored.Domains, ",") != strings.Join(payload.Domains, ",") || strings.Join(loadedSite.Domains, ",") != strings.Join(payload.Domains, ",") {
		t.Fatalf("site domains diverged after reload: sqlite=%v yaml=%v want=%v", stored.Domains, loadedSite.Domains, payload.Domains)
	}
	if strings.Join(stored.Upstreams, ",") != strings.Join(payload.Upstreams, ",") || len(loadedSite.Upstreams) != 2 || loadedSite.Upstreams[0].Address != payload.Upstreams[0] || loadedSite.Upstreams[1].Address != payload.Upstreams[1] {
		t.Fatalf("site upstreams diverged after reload: sqlite=%v yaml=%v want=%v", stored.Upstreams, loadedSite.Upstreams, payload.Upstreams)
	}
	if stored.WAFMode != "monitor" || loadedSite.WAF.Mode != "monitor" || loadedSite.WAF.Performance.ProxyTimeout != 47*time.Second {
		t.Fatalf("site runtime fields diverged after reload: sqlite_mode=%q yaml_mode=%q yaml_timeout=%s", stored.WAFMode, loadedSite.WAF.Mode, loadedSite.WAF.Performance.ProxyTimeout)
	}
}

func TestUpdateSiteRollsBackStoreWhenRuntimeSyncFails(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	handler.OnSitesChanged = func(sites []config.SiteConfig) error {
		if len(sites) == 1 && sites[0].Name == "runtime-rejected-site" {
			return errors.New("runtime reload failed")
		}
		return nil
	}
	payload := site
	payload.Name = "runtime-rejected-site"
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal update payload: %v", err)
	}

	router := chi.NewRouter()
	router.Put("/sites/{id}", handler.UpdateSite)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/sites/"+site.ID, bytes.NewReader(raw)))
	assertSiteAPIError(t, recorder, http.StatusInternalServerError, "CONFIG_SYNC_ERROR")

	stored, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("reload site after failed sync: %v", err)
	}
	loaded, err := config.Load(handler.ConfigPath)
	if err != nil {
		t.Fatalf("reload config after failed sync: %v", err)
	}
	if stored == nil || len(loaded.Sites) != 1 || len(handler.Config.Sites) != 1 {
		t.Fatalf("site state missing after failed sync: sqlite=%+v yaml=%+v memory=%+v", stored, loaded.Sites, handler.Config.Sites)
	}
	if stored.Name != site.Name || loaded.Sites[0].Name != site.Name || handler.Config.Sites[0].Name != site.Name {
		t.Fatalf("failed site update was not rolled back consistently: sqlite=%q yaml=%q memory=%q want=%q", stored.Name, loaded.Sites[0].Name, handler.Config.Sites[0].Name, site.Name)
	}
	if !stored.UpdatedAt.Equal(site.UpdatedAt) {
		t.Fatalf("failed site update changed audit timestamp: sqlite=%s want=%s", stored.UpdatedAt, site.UpdatedAt)
	}
}

func TestCreateSiteRollsBackStoreWhenRuntimeSyncFails(t *testing.T) {
	handler, store, original := newSiteTestHandler(t)
	handler.OnSitesChanged = func(sites []config.SiteConfig) error {
		for _, site := range sites {
			if site.Name == "runtime-rejected-create" {
				return errors.New("runtime reload failed")
			}
		}
		return nil
	}
	payload := storage.Site{ID: "runtime-rejected-create", Name: "runtime-rejected-create", Domains: []string{"create.example.test"}, Upstreams: []string{"127.0.0.1:9300"}, WAFEnabled: true, Enabled: true}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal create payload: %v", err)
	}
	router := chi.NewRouter()
	router.Post("/sites", handler.CreateSite)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/sites", bytes.NewReader(raw)))
	assertSiteAPIError(t, recorder, http.StatusInternalServerError, "CONFIG_SYNC_ERROR")
	stored, err := store.GetSite(context.Background(), payload.ID)
	if err != nil {
		t.Fatalf("reload failed create: %v", err)
	}
	if stored != nil || len(handler.Config.Sites) != 1 || handler.Config.Sites[0].Name != original.Name {
		t.Fatalf("failed create was not rolled back: sqlite=%+v memory=%+v", stored, handler.Config.Sites)
	}
}

func TestDeleteSiteRollsBackStoreWhenRuntimeSyncFails(t *testing.T) {
	handler, store, _ := newSiteTestHandler(t)
	second := storage.Site{ID: "runtime-rejected-delete", Name: "runtime-rejected-delete", Domains: []string{"delete.example.test"}, Upstreams: []string{"127.0.0.1:9400"}, WAFEnabled: true, Enabled: true}
	if err := store.CreateSite(context.Background(), &second); err != nil {
		t.Fatalf("create second site: %v", err)
	}
	if err := handler.syncSites(httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatalf("sync second site baseline: %v", err)
	}
	handler.OnSitesChanged = func(sites []config.SiteConfig) error {
		if len(sites) == 1 {
			return errors.New("runtime reload failed")
		}
		return nil
	}
	router := chi.NewRouter()
	router.Delete("/sites/{id}", handler.DeleteSite)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/sites/"+second.ID, nil))
	assertSiteAPIError(t, recorder, http.StatusInternalServerError, "CONFIG_SYNC_ERROR")
	stored, err := store.GetSite(context.Background(), second.ID)
	if err != nil {
		t.Fatalf("reload failed delete: %v", err)
	}
	loaded, err := config.Load(handler.ConfigPath)
	if err != nil {
		t.Fatalf("reload config after failed delete: %v", err)
	}
	if stored == nil || len(loaded.Sites) != 2 || len(handler.Config.Sites) != 2 {
		t.Fatalf("failed delete was not rolled back: sqlite=%+v yaml=%+v memory=%+v", stored, loaded.Sites, handler.Config.Sites)
	}
}

func TestSiteStoreRollbackFailureFreezesConfigWrites(t *testing.T) {
	handler, store, _ := newSiteTestHandler(t)
	failingStore := &siteFailureStore{Store: store, deleteErr: errors.New("rollback delete failed")}
	handler.Store = failingStore
	handler.OnSitesChanged = func(sites []config.SiteConfig) error {
		if len(sites) > 1 {
			return errors.New("runtime reload failed")
		}
		return nil
	}
	payload := storage.Site{ID: "rollback-failure", Name: "rollback-failure", Domains: []string{"rollback.example.test"}, Upstreams: []string{"127.0.0.1:9500"}, WAFEnabled: true, Enabled: true}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal create payload: %v", err)
	}
	router := chi.NewRouter()
	router.Post("/sites", handler.CreateSite)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/sites", bytes.NewReader(raw)))
	assertSiteAPIError(t, recorder, http.StatusInternalServerError, "CONFIG_SYNC_ERROR")
	if !handler.configWriteFrozen || !strings.Contains(handler.configFreezeReason, "rollback delete failed") {
		t.Fatalf("rollback failure did not freeze writes: frozen=%v reason=%q", handler.configWriteFrozen, handler.configFreezeReason)
	}
	callsBefore := failingStore.totalCalls()
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/sites", bytes.NewReader(raw)))
	assertSiteAPIError(t, recorder, http.StatusLocked, "CONFIG_WRITES_FROZEN")
	if failingStore.totalCalls() != callsBefore {
		t.Fatalf("frozen write reached store: before=%d after=%d", callsBefore, failingStore.totalCalls())
	}
}

func TestSiteMutationsRejectClusterProtectionModeBeforeStoreAccess(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			handler, store, site := newSiteTestHandler(t)
			clusterConfig := minimumHAHandlerConfig()
			handler.Config.Deployment = clusterConfig.Deployment
			handler.Config.Cluster = clusterConfig.Cluster
			observedStore := &siteFailureStore{Store: store}
			handler.Store = observedStore

			router := chi.NewRouter()
			var request *http.Request
			switch operation {
			case "create":
				router.Post("/sites", handler.CreateSite)
				request = httptest.NewRequest(http.MethodPost, "/sites", strings.NewReader(`{"name":"blocked"}`))
			case "update":
				router.Put("/sites/{id}", handler.UpdateSite)
				request = httptest.NewRequest(http.MethodPut, "/sites/"+site.ID, strings.NewReader(`{"name":"blocked"}`))
			case "delete":
				router.Delete("/sites/{id}", handler.DeleteSite)
				request = httptest.NewRequest(http.MethodDelete, "/sites/"+site.ID, nil)
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			assertSiteAPIError(t, recorder, http.StatusLocked, "CLUSTER_PROTECTION_MODE")
			if observedStore.totalCalls() != 0 {
				t.Fatalf("protected %s accessed site store %d times", operation, observedStore.totalCalls())
			}
		})
	}
}

func TestDeleteSiteRejectsLastSiteBeforeMutatingStore(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)

	router := chi.NewRouter()
	router.Delete("/sites/{id}", handler.DeleteSite)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/sites/"+site.ID, nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected last site delete to be rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "at least one site is required") {
		t.Fatalf("expected explicit last-site error, body=%s", recorder.Body.String())
	}
	sites, err := store.ListSites(context.Background())
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	if len(sites) != 1 || sites[0].ID != site.ID {
		t.Fatalf("site should remain in store after rejected delete, got %+v", sites)
	}
}

func TestUpdateSiteRejectsInvalidRewriteBeforeMutatingStore(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	site.Advanced.Rewrite = []storage.SiteRewriteRule{{
		ID:           "bad-rewrite",
		Pattern:      "(",
		Replacement:  "/new",
		RedirectCode: 302,
		Enabled:      true,
	}}
	raw, _ := json.Marshal(site)

	router := chi.NewRouter()
	router.Put("/sites/{id}", handler.UpdateSite)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/sites/"+site.ID, bytes.NewReader(raw))
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid rewrite to be rejected, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	stored, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("get stored site: %v", err)
	}
	if stored == nil {
		t.Fatal("stored site disappeared")
	}
	if len(stored.Advanced.Rewrite) != 0 {
		t.Fatalf("invalid rewrite should not be persisted, got %+v", stored.Advanced.Rewrite)
	}
}

func TestUpdateSiteNormalizesDefaultsBeforePersisting(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	payload := storage.Site{
		ID:         site.ID,
		Name:       "minimal-site",
		Domains:    []string{"minimal.example.test"},
		Upstreams:  []string{"127.0.0.1:9010"},
		WAFEnabled: true,
		Enabled:    true,
	}
	raw, _ := json.Marshal(payload)

	router := chi.NewRouter()
	router.Put("/sites/{id}", handler.UpdateSite)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/sites/"+site.ID, bytes.NewReader(raw))
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected minimal update to be accepted, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	stored, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("get stored site: %v", err)
	}
	if stored == nil {
		t.Fatal("stored site disappeared")
	}
	if stored.ListenPort != 80 {
		t.Fatalf("listen port should default to 80, got %d", stored.ListenPort)
	}
	if stored.LoadBalance != "round_robin" {
		t.Fatalf("load balance should be defaulted, got %q", stored.LoadBalance)
	}
	if stored.WAFMode != "block" {
		t.Fatalf("waf mode should default to block, got %q", stored.WAFMode)
	}
	if stored.Advanced.Origin.ProxyTimeout != "30s" {
		t.Fatalf("proxy timeout should be defaulted, got %q", stored.Advanced.Origin.ProxyTimeout)
	}
	if stored.Advanced.Origin.MaxBodyBytes == 0 || stored.Advanced.Origin.MaxHeaderSize == 0 {
		t.Fatalf("origin limits should be defaulted, got body=%d header=%d", stored.Advanced.Origin.MaxBodyBytes, stored.Advanced.Origin.MaxHeaderSize)
	}
	if !stored.Advanced.Protection.SemanticSQL || !stored.Advanced.Protection.SemanticXSS || !stored.Advanced.Protection.SemanticSSRF {
		t.Fatalf("semantic protections should be enabled by default, got %+v", stored.Advanced.Protection)
	}
}

func TestSiteResponsesRedactInlinePrivateKeyAndACMEEnv(t *testing.T) {
	handler, store, site := newSiteTestHandler(t)
	site.Advanced.Certificate.Mode = "inline"
	site.Advanced.Certificate.CertPEM = "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
	site.Advanced.Certificate.KeyPEM = "-----BEGIN PRIVATE KEY-----\nsite-key-secret\n-----END PRIVATE KEY-----"
	site.Advanced.Certificate.ACME = storage.SiteACMEConfig{
		ProviderID: "cf",
		DNSAPI:     "dns_cf",
		Env:        map[string]string{"CF_TOKEN": "site-acme-secret"},
		Domains:    []string{"example.test"},
	}
	if err := store.UpdateSite(context.Background(), &site); err != nil {
		t.Fatalf("update site: %v", err)
	}

	router := chi.NewRouter()
	router.Get("/sites", handler.ListSites)
	router.Get("/sites/{id}", handler.GetSite)

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "list", path: "/sites"},
		{name: "get", path: "/sites/" + site.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, tc.path, nil)
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("expected site response ok, code=%d body=%s", recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			if strings.Contains(body, "site-key-secret") || strings.Contains(body, "site-acme-secret") {
				t.Fatalf("site response leaked private key or ACME env: %s", body)
			}
			if !strings.Contains(body, `"env":{"CF_TOKEN":""}`) {
				t.Fatalf("site response should expose ACME env keys without values, body=%s", body)
			}
		})
	}
}

func TestIssueSiteACMEIgnoresUntrustedRuntimeFields(t *testing.T) {
	handler, _, site := newSiteTestHandler(t)
	handler.Config.ACME.ACMESHPath = "/opt/cheesewaf/bin/acme.sh"
	handler.Config.ACME.Home = filepath.Join(t.TempDir(), "acme-home")
	handler.Config.ACME.CertDir = filepath.Join(t.TempDir(), "certs")
	handler.Config.ACME.ReloadCommand = "systemctl reload cheesewaf"
	issuer := &recordingACMEIssuer{}
	handler.ACMEIssuer = issuer

	body := []byte(`{
		"provider_id":"cf",
		"dns_api":"dns_cf",
		"dns_env":{"CF_TOKEN":"secret"},
		"account_email":"ops@example.test",
		"server":"letsencrypt",
		"key_type":"ec-256",
		"acme_sh_path":"/tmp/evil.sh",
		"home":"/tmp/evil-home",
		"cert_dir":"/tmp/evil-certs",
		"reload_cmd":"sh -c evil",
		"auto_renew":true,
		"notify":true
	}`)
	router := chi.NewRouter()
	router.Post("/sites/{id}/acme/issue", handler.IssueSiteACME)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/sites/"+site.ID+"/acme/issue", bytes.NewReader(body))
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected issue ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if issuer.request.ACMESHPath != handler.Config.ACME.ACMESHPath {
		t.Fatalf("site payload must not override acme.sh path, got %q", issuer.request.ACMESHPath)
	}
	if issuer.request.Home != handler.Config.ACME.Home {
		t.Fatalf("site payload must not override acme home, got %q", issuer.request.Home)
	}
	if issuer.request.ReloadCmd != handler.Config.ACME.ReloadCommand {
		t.Fatalf("site payload must not override reload command, got %q", issuer.request.ReloadCmd)
	}
	if strings.Contains(issuer.request.CertDir, "evil") || !strings.HasPrefix(issuer.request.CertDir, handler.Config.ACME.CertDir) {
		t.Fatalf("site payload must not override cert dir, got %q", issuer.request.CertDir)
	}
	stored, err := handler.Store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatalf("get site: %v", err)
	}
	if stored.Advanced.Certificate.ACME.ReloadCommand != handler.Config.ACME.ReloadCommand {
		t.Fatalf("stored acme runtime should come from trusted config, got %+v", stored.Advanced.Certificate.ACME)
	}
	if strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("acme issue response leaked DNS env value: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"env_keys":["CF_TOKEN"]`) || !strings.Contains(recorder.Body.String(), `"env_set":true`) {
		t.Fatalf("acme issue response should expose DNS env presence without values, body=%s", recorder.Body.String())
	}
}

func newSiteTestHandler(t *testing.T) (*Handler, *storage.SQLiteStore, storage.Site) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	site := storage.Site{
		ID:         "site-test",
		Name:       "site-test",
		Domains:    []string{"example.test"},
		Upstreams:  []string{"127.0.0.1:9000"},
		ListenPort: 80,
		WAFEnabled: true,
		WAFMode:    "block",
		Enabled:    true,
	}
	if err := store.CreateSite(ctx, &site); err != nil {
		t.Fatalf("create site: %v", err)
	}
	sites, err := store.ListSites(ctx)
	if err != nil {
		t.Fatalf("list sites: %v", err)
	}
	cfg := config.Default()
	cfg.Sites = storage.SitesToConfig(sites)
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return New(Options{Config: &cfg, ConfigPath: configPath, Store: store}), store, sites[0]
}

type siteFailureStore struct {
	storage.Store
	createErr error
	updateErr error
	deleteErr error

	listCalls   int
	getCalls    int
	createCalls int
	updateCalls int
	deleteCalls int
}

func (s *siteFailureStore) ListSites(ctx context.Context) ([]storage.Site, error) {
	s.listCalls++
	return s.Store.ListSites(ctx)
}

func (s *siteFailureStore) GetSite(ctx context.Context, id string) (*storage.Site, error) {
	s.getCalls++
	return s.Store.GetSite(ctx, id)
}

func (s *siteFailureStore) CreateSite(ctx context.Context, site *storage.Site) error {
	s.createCalls++
	if s.createErr != nil {
		return s.createErr
	}
	return s.Store.CreateSite(ctx, site)
}

func (s *siteFailureStore) UpdateSite(ctx context.Context, site *storage.Site) error {
	s.updateCalls++
	if s.updateErr != nil {
		return s.updateErr
	}
	return s.Store.UpdateSite(ctx, site)
}

func (s *siteFailureStore) DeleteSite(ctx context.Context, id string) error {
	s.deleteCalls++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Store.DeleteSite(ctx, id)
}

func (s *siteFailureStore) totalCalls() int {
	return s.listCalls + s.getCalls + s.createCalls + s.updateCalls + s.deleteCalls
}

func assertSiteAPIError(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d, want %d: %s", recorder.Code, status, recorder.Body.String())
	}
	var envelope struct {
		Data  json.RawMessage `json:"data"`
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v: %s", err, recorder.Body.String())
	}
	if envelope.Error == nil || envelope.Error.Code != code {
		t.Fatalf("error code=%v, want %q: %s", envelope.Error, code, recorder.Body.String())
	}
	if len(envelope.Data) != 0 && string(envelope.Data) != "null" {
		t.Fatalf("error response included success data: %s", recorder.Body.String())
	}
}

type recordingACMEIssuer struct {
	request acme.IssueRequest
}

func (i *recordingACMEIssuer) Providers() []acme.DNSProvider {
	return nil
}

func (i *recordingACMEIssuer) Issue(_ context.Context, req acme.IssueRequest) (acme.IssueResult, error) {
	i.request = req
	now := time.Now().UTC()
	return acme.IssueResult{
		RunID:      "acme-test",
		SiteID:     req.SiteID,
		Domains:    append([]string(nil), req.Domains...),
		CertFile:   filepath.Join(req.CertDir, "fullchain.cer"),
		Fullchain:  filepath.Join(req.CertDir, "fullchain.cer"),
		KeyFile:    filepath.Join(req.CertDir, "site.key"),
		KeyType:    req.KeyType,
		Server:     req.Server,
		DNSAPI:     req.DNSAPI,
		IssuedAt:   now,
		RenewAfter: now.Add(60 * 24 * time.Hour),
		AutoRenew:  req.AutoRenew,
		Notify:     req.Notify,
	}, nil
}
