package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/setup"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestEnsureAdminTLSCertificateGeneratesOnce(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Server.AdminListen = "0.0.0.0:9443"
	cfg.Server.AdminTLS.Enabled = true
	cfg.Server.AdminTLS.SelfSigned = true
	cfg.Server.AdminTLS.CertFile = filepath.Join(root, "certs", "admin.crt")
	cfg.Server.AdminTLS.KeyFile = filepath.Join(root, "certs", "admin.key")

	if err := ensureAdminTLSCertificate(&cfg); err != nil {
		t.Fatal(err)
	}
	certBefore, err := os.ReadFile(cfg.Server.AdminTLS.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(cfg.Server.AdminTLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(certBefore) == 0 || len(keyBefore) == 0 {
		t.Fatal("generated admin TLS material is empty")
	}
	if err = ensureAdminTLSCertificate(&cfg); err != nil {
		t.Fatal(err)
	}
	certAfter, _ := os.ReadFile(cfg.Server.AdminTLS.CertFile)
	keyAfter, _ := os.ReadFile(cfg.Server.AdminTLS.KeyFile)
	if !bytes.Equal(certBefore, certAfter) || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("existing admin TLS material was unexpectedly rotated")
	}
}

func TestRepairRuntimeConfigPersistsSecretWhenConfigIsReadOnly(t *testing.T) {
	root := t.TempDir()
	configTarget := filepath.Join(root, "config-target")
	if err := os.Mkdir(configTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Setup.RuntimeDir = filepath.Join(root, "run")
	cfg.Protection.Bot.Secret = config.BotSecretPlaceholder
	if err := repairRuntimeConfig(configTarget, &cfg); err != nil {
		t.Fatal(err)
	}
	firstSecret := cfg.Protection.Bot.Secret
	if config.IsWeakBotSecret(firstSecret) {
		t.Fatal("runtime fallback retained a weak Bot challenge secret")
	}
	if _, err := os.Stat(filepath.Join(cfg.Setup.RuntimeDir, "bot_secret")); err != nil {
		t.Fatalf("runtime secret was not persisted: %v", err)
	}

	reloaded := config.Default()
	reloaded.Setup.RuntimeDir = cfg.Setup.RuntimeDir
	reloaded.Protection.Bot.Secret = config.BotSecretPlaceholder
	if err := repairRuntimeConfig(configTarget, &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.Protection.Bot.Secret != firstSecret {
		t.Fatal("runtime fallback secret was not stable across reload")
	}
}

func TestResolveWebDirFindsReleaseAssetsBesideExecutable(t *testing.T) {
	originalExecutablePath := executablePath
	originalWebDir := os.Getenv("CHEESEWAF_WEB_DIR")
	t.Cleanup(func() {
		executablePath = originalExecutablePath
		_ = os.Setenv("CHEESEWAF_WEB_DIR", originalWebDir)
	})
	_ = os.Unsetenv("CHEESEWAF_WEB_DIR")
	root := t.TempDir()
	webDir := filepath.Join(root, "web", "dist")
	if err := os.MkdirAll(webDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<!doctype html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return filepath.Join(root, "cheesewaf"), nil }
	if got := resolveWebDir(); got != webDir {
		t.Fatalf("resolveWebDir() = %q, want %q", got, webDir)
	}
}

func TestValidateStartupUsersRejectsCompletedSetupWithoutAdministrator(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := storage.OpenSQLite(filepath.Join(dataDir, "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := setup.MarkComplete(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := validateStartupUsers(ctx, dataDir, store); err == nil || !strings.Contains(err.Error(), "no administrator") {
		t.Fatalf("expected missing administrator error, got %v", err)
	}
	if err := store.CreateUser(ctx, &storage.User{Username: "reader", PasswordHash: "hash", Role: "readonly"}); err != nil {
		t.Fatal(err)
	}
	if err := validateStartupUsers(ctx, dataDir, store); err == nil {
		t.Fatal("expected readonly-only store to remain invalid")
	}
	if err := store.CreateUser(ctx, &storage.User{Username: "Cheese", PasswordHash: "hash", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := validateStartupUsers(ctx, dataDir, store); err != nil {
		t.Fatalf("expected administrator to satisfy integrity check: %v", err)
	}
}

func TestValidateStartupUsersAllowsIncompleteFirstRun(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	store, err := storage.OpenSQLite(filepath.Join(dataDir, "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := validateStartupUsers(ctx, dataDir, store); err != nil {
		t.Fatalf("first-run setup should remain available: %v", err)
	}
}

func TestAdminHandlerServesSPAAndKeepsAPI(t *testing.T) {
	webDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("cheesewaf-ui"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	assets := filepath.Join(webDir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assets, "app.js"), []byte("console.log('cw')"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	t.Setenv("CHEESEWAF_WEB_DIR", webDir)

	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	})
	handler := adminHandler(&config.Config{}, apiHandler, "test-admin-secret")

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/", want: "cheesewaf-ui"},
		{path: "/sites/default", want: "cheesewaf-ui"},
		{path: "/assets/app.js", want: "console.log('cw')"},
		{path: "/api/system", want: "api:/api/system"},
		{path: "/health", want: "api:/health"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Body.String() != tc.want {
			t.Fatalf("%s: got %q want %q", tc.path, rr.Body.String(), tc.want)
		}
		assertAdminSecurityHeaders(t, rr, false)
	}

	missingAsset := httptest.NewRecorder()
	handler.ServeHTTP(missingAsset, httptest.NewRequest(http.MethodGet, "/assets/old-hash.js", nil))
	if missingAsset.Code != http.StatusNotFound || strings.Contains(missingAsset.Body.String(), "cheesewaf-ui") {
		t.Fatalf("missing static assets must not fall back to SPA, got %d: %s", missingAsset.Code, missingAsset.Body.String())
	}

	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rrMetrics := httptest.NewRecorder()
	handler.ServeHTTP(rrMetrics, reqMetrics)
	if rrMetrics.Code != http.StatusNotFound {
		t.Fatalf("/metrics should not fall back to SPA when public metrics are disabled, got %d: %s", rrMetrics.Code, rrMetrics.Body.String())
	}
	assertAdminSecurityHeaders(t, rrMetrics, false)

	publicMetricsHandler := adminHandler(&config.Config{Monitor: config.MonitorConfig{Prometheus: config.PrometheusConfig{Enabled: true, Path: "/metrics", Public: true}}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("metrics:" + r.URL.Path))
	}), "test-admin-secret")
	rrPublicMetrics := httptest.NewRecorder()
	publicMetricsHandler.ServeHTTP(rrPublicMetrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rrPublicMetrics.Body.String() != "metrics:/metrics" {
		t.Fatalf("public /metrics should route to api handler, got %q", rrPublicMetrics.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "https://cheesewaf.local/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assertAdminSecurityHeaders(t, rr, true)
}

func TestAdminHandlerSecurityEntryGatesConsole(t *testing.T) {
	webDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("cheesewaf-login"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	t.Setenv("CHEESEWAF_WEB_DIR", webDir)

	cfg := config.Default()
	cfg.Console.Login.SecurityEntry.Enabled = true
	cfg.Console.Login.SecurityEntry.Path = "/secure-admin"
	cfg.Console.Login.SecurityEntry.CookieName = "cw_entry_test"
	handler := adminHandler(&cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	}), "security-entry-secret")

	direct := httptest.NewRecorder()
	handler.ServeHTTP(direct, httptest.NewRequest(http.MethodGet, "/login", nil))
	if direct.Code != http.StatusTeapot || !strings.Contains(direct.Body.String(), "418 I'm a teapot") {
		t.Fatalf("expected direct login to return 418, got %d: %s", direct.Code, direct.Body.String())
	}

	wrong := httptest.NewRecorder()
	handler.ServeHTTP(wrong, httptest.NewRequest(http.MethodGet, "/secure-admin-wrong", nil))
	if wrong.Code != http.StatusTeapot {
		t.Fatalf("expected wrong entry to return 418, got %d: %s", wrong.Code, wrong.Body.String())
	}

	entry := httptest.NewRecorder()
	handler.ServeHTTP(entry, httptest.NewRequest(http.MethodGet, "/secure-admin", nil))
	if entry.Code != http.StatusFound {
		t.Fatalf("expected security entry redirect, got %d: %s", entry.Code, entry.Body.String())
	}
	if got := entry.Header().Get("Location"); got != "/login" {
		t.Fatalf("security entry redirected to %q, want /login", got)
	}
	cookies := entry.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "cw_entry_test" || !cookies[0].HttpOnly {
		t.Fatalf("expected signed HttpOnly entry cookie, got %+v", cookies)
	}

	allowedReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	allowedReq.AddCookie(cookies[0])
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, allowedReq)
	if allowed.Code != http.StatusOK || allowed.Body.String() != "cheesewaf-login" {
		t.Fatalf("expected login with entry cookie to serve SPA, got %d: %s", allowed.Code, allowed.Body.String())
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health", nil))
	if health.Code != http.StatusOK || health.Body.String() != "api:/health" {
		t.Fatalf("expected health to remain available, got %d: %s", health.Code, health.Body.String())
	}
}

func TestAdminHandlerSecurityEntryReadsUpdatedConfig(t *testing.T) {
	webDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("cheesewaf-login"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	t.Setenv("CHEESEWAF_WEB_DIR", webDir)

	cfg := config.Default()
	cfg.Console.Login.SecurityEntry.Enabled = true
	cfg.Console.Login.SecurityEntry.Path = "/first-door"
	cfg.Console.Login.SecurityEntry.CookieName = "cw_entry_dynamic"
	handler := adminHandler(&cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api:" + r.URL.Path))
	}), "dynamic-entry-secret")

	cfg.Console.Login.SecurityEntry.Path = "/second-door"

	oldEntry := httptest.NewRecorder()
	handler.ServeHTTP(oldEntry, httptest.NewRequest(http.MethodGet, "/first-door", nil))
	if oldEntry.Code != http.StatusTeapot {
		t.Fatalf("expected old security entry to be rejected after config update, got %d", oldEntry.Code)
	}

	newEntry := httptest.NewRecorder()
	handler.ServeHTTP(newEntry, httptest.NewRequest(http.MethodGet, "/second-door", nil))
	if newEntry.Code != http.StatusFound {
		t.Fatalf("expected updated security entry to redirect, got %d: %s", newEntry.Code, newEntry.Body.String())
	}
}

func TestAdminHandlerSecurityEntryFailsClosedWhenNonceUnavailable(t *testing.T) {
	webDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte("cheesewaf-login"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	t.Setenv("CHEESEWAF_WEB_DIR", webDir)

	previousNonceReader := readAdminEntryNonce
	readAdminEntryNonce = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	defer func() { readAdminEntryNonce = previousNonceReader }()

	cfg := config.Default()
	cfg.Console.Login.SecurityEntry.Enabled = true
	cfg.Console.Login.SecurityEntry.Path = "/secure-admin"
	cfg.Console.Login.SecurityEntry.CookieName = "cw_entry_test"
	handler := adminHandler(&cfg, http.NotFoundHandler(), "security-entry-secret")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/secure-admin", nil))
	if recorder.Code != http.StatusTeapot {
		t.Fatalf("expected entropy failure to return 418, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("expected no entry cookie when nonce generation fails, got %q", got)
	}
	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect when nonce generation fails, got %q", got)
	}
}

func TestAdminHandlerCachesAndCompressesStaticAssets(t *testing.T) {
	webDir := t.TempDir()
	assets := filepath.Join(webDir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(webDir, "index.html"), []byte(strings.Repeat("index", 100)), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(assets, "app.js"), []byte(strings.Repeat("console.log('cw');", 80)), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}
	t.Setenv("CHEESEWAF_WEB_DIR", webDir)
	handler := adminHandler(&config.Config{}, http.NotFoundHandler(), "cache-secret")

	req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected asset 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Fatalf("unexpected asset cache header %q", got)
	}
	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("expected gzip asset, got %q", got)
	}

	index := httptest.NewRecorder()
	handler.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/login", nil))
	if got := index.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("unexpected index cache header %q", got)
	}
}

func assertAdminSecurityHeaders(t *testing.T, rr *httptest.ResponseRecorder, wantHSTS bool) {
	t.Helper()
	for name, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Frame-Options":              "DENY",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=()",
	} {
		if got := rr.Header().Get(name); got != want {
			t.Fatalf("header %s = %q, want %q", name, got, want)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"connect-src 'self' ws: wss:",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("Content-Security-Policy %q does not contain %q", csp, want)
		}
	}
	hsts := rr.Header().Get("Strict-Transport-Security")
	if wantHSTS && hsts == "" {
		t.Fatal("expected HSTS on HTTPS admin response")
	}
	if !wantHSTS && hsts != "" {
		t.Fatalf("did not expect HSTS on HTTP admin response, got %q", hsts)
	}
}

func TestBuildPipelineHonorsNoSQLSemanticSwitch(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{
				ID:      "default",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: config.SemanticEngineSwitches{
						NoSQL: true,
					},
				},
			},
		},
	}
	pipeline, err := buildPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{"username":{"$ne":null},"password":{"$ne":null}}`))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pipeline.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "nosqli" {
		t.Fatalf("expected NoSQLi detection from site semantic switch, got %+v", result)
	}
}

func TestBuildPipelineHonorsSSTISemanticSwitch(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{
				ID:      "default",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: config.SemanticEngineSwitches{
						SSTI: true,
					},
				},
			},
		},
	}
	pipeline, err := buildPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "/profile", bytes.NewBufferString(`display_name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pipeline.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "ssti" {
		t.Fatalf("expected SSTI detection from site semantic switch, got %+v", result)
	}
}

func TestBuildPipelineScopesSemanticSwitchesPerSite(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{
				ID:      "site-a",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: config.SemanticEngineSwitches{
						SQL: true,
					},
				},
			},
			{
				ID:      "site-b",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: config.SemanticEngineSwitches{
						NoSQL: true,
					},
				},
			},
		},
	}
	pipeline, err := buildPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"username":{"$ne":null},"password":{"$ne":null}}`
	reqA, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(body))
	reqA.Header.Set("Content-Type", "application/json")
	ctxA, err := engine.NewRequestContext(reqA, "site-a")
	if err != nil {
		t.Fatal(err)
	}
	resultA, err := pipeline.Detect(context.Background(), ctxA)
	if err != nil {
		t.Fatal(err)
	}
	if resultA != nil && resultA.Detected {
		t.Fatalf("expected site-a NoSQL switch to remain disabled, got %+v", resultA)
	}

	reqB, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(body))
	reqB.Header.Set("Content-Type", "application/json")
	ctxB, err := engine.NewRequestContext(reqB, "site-b")
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := pipeline.Detect(context.Background(), ctxB)
	if err != nil {
		t.Fatal(err)
	}
	if resultB == nil || !resultB.Detected || resultB.Category != "nosqli" {
		t.Fatalf("expected site-b NoSQLi detection, got %+v", resultB)
	}
}

func TestBuildPipelineScopesCustomRulesPerSite(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{
				ID:      "site-a",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
				},
			},
			{
				ID:      "site-b",
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled: true,
					Mode:    "block",
					CustomRules: []config.CustomRuleConfig{
						{
							ID:       "block-admin-probe",
							Name:     "Block admin probe",
							Pattern:  `admin_probe_token`,
							Location: "uri",
							Action:   "block",
							Severity: "high",
							Enabled:  true,
						},
					},
				},
			},
		},
	}
	pipeline, err := buildPipeline(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reqA, _ := http.NewRequest(http.MethodGet, "/admin_probe_token", nil)
	ctxA, err := engine.NewRequestContext(reqA, "site-a")
	if err != nil {
		t.Fatal(err)
	}
	resultA, err := pipeline.Detect(context.Background(), ctxA)
	if err != nil {
		t.Fatal(err)
	}
	if resultA != nil && resultA.Detected {
		t.Fatalf("expected site-a custom rule isolation, got %+v", resultA)
	}

	reqB, _ := http.NewRequest(http.MethodGet, "/admin_probe_token", nil)
	ctxB, err := engine.NewRequestContext(reqB, "site-b")
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := pipeline.Detect(context.Background(), ctxB)
	if err != nil {
		t.Fatal(err)
	}
	if resultB == nil || !resultB.Detected || resultB.Category != "custom_rule" {
		t.Fatalf("expected site-b custom rule detection, got %+v", resultB)
	}
}
