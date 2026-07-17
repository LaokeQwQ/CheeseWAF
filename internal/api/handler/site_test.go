package handler

import (
	"bytes"
	"context"
	"encoding/json"
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
