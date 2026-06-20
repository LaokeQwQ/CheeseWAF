package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestRouterRequiresBearerForManagementAPI(t *testing.T) {
	router, _, readerToken := newAuthzTestRouter(t)

	for _, tc := range []struct {
		name   string
		method string
		path   string
	}{
		{name: "system", method: http.MethodGet, path: "/api/system"},
		{name: "realtime events", method: http.MethodGet, path: "/api/realtime/events"},
		{name: "realtime websocket", method: http.MethodGet, path: "/api/realtime/ws"},
		{name: "logs", method: http.MethodGet, path: "/api/logs"},
		{name: "ui error report", method: http.MethodPost, path: "/api/ui/errors"},
		{name: "backup export", method: http.MethodPost, path: "/api/backup/export"},
		{name: "block page preview", method: http.MethodPost, path: "/api/block-pages/preview"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := perform(router, tc.method, tc.path, "", nil)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 without bearer token, got %d: %s", recorder.Code, recorder.Body.String())
			}
			traceID := recorder.Header().Get("X-CheeseWAF-Trace-ID")
			eventID := recorder.Header().Get("X-CheeseWAF-Event-ID")
			if traceID == "" || eventID == "" || traceID != eventID {
				t.Fatalf("expected matching trace/event headers, trace=%q event=%q", traceID, eventID)
			}
			var body struct {
				Error struct {
					TraceID string `json:"trace_id"`
					EventID string `json:"event_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode unauthorized error: %v", err)
			}
			if body.Error.TraceID != traceID || body.Error.EventID != eventID {
				t.Fatalf("expected matching trace/event body fields, header trace=%q event=%q body=%+v", traceID, eventID, body.Error)
			}
		})
	}

	t.Run("cookie token is ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "cheesewaf-token", Value: readerToken})
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected cookie-only request to stay unauthorized, got %d: %s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestRouterReadonlyCannotMutateManagementAPI(t *testing.T) {
	router, _, readerToken := newAuthzTestRouter(t)

	read := perform(router, http.MethodGet, "/api/system", readerToken, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("readonly user should be allowed to read system status, got %d: %s", read.Code, read.Body.String())
	}

	writeCases := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{name: "system update", method: http.MethodPut, path: "/api/system", body: []byte(`{}`)},
		{name: "storage test", method: http.MethodPost, path: "/api/system/storage/test", body: []byte(`{"backend":"sqlite"}`)},
		{name: "create user", method: http.MethodPost, path: "/api/users", body: []byte(`{"username":"next","password":"correct-horse-battery","role":"readonly"}`)},
		{name: "update user", method: http.MethodPut, path: "/api/users/admin-id", body: []byte(`{"role":"admin"}`)},
		{name: "disable 2fa", method: http.MethodPost, path: "/api/users/admin-id/2fa/disable", body: []byte(`{}`)},
		{name: "ip tags", method: http.MethodPut, path: "/api/ip/tags", body: []byte(`{"tags":{}}`)},
		{name: "threat providers", method: http.MethodPut, path: "/api/ip/threat-intel/providers", body: []byte(`{"providers":[]}`)},
		{name: "threat import", method: http.MethodPost, path: "/api/ip/threat-intel/import", body: []byte(`{"entries":[]}`)},
		{name: "threat sync", method: http.MethodPost, path: "/api/ip/threat-intel/sync", body: []byte(`{}`)},
		{name: "protection policy", method: http.MethodPut, path: "/api/protection/policy", body: []byte(`{}`)},
		{name: "create site", method: http.MethodPost, path: "/api/sites", body: []byte(`{}`)},
		{name: "delete site", method: http.MethodDelete, path: "/api/sites/default", body: nil},
		{name: "create rule", method: http.MethodPost, path: "/api/rules", body: []byte(`{}`)},
		{name: "delete rule", method: http.MethodDelete, path: "/api/rules/rule-1", body: nil},
		{name: "scheduler tasks", method: http.MethodPut, path: "/api/scheduler/tasks", body: []byte(`{"tasks":[]}`)},
		{name: "edge policy", method: http.MethodPut, path: "/api/edge", body: []byte(`{}`)},
		{name: "ai config", method: http.MethodPut, path: "/api/ai/config", body: []byte(`{}`)},
		{name: "storage cleanup", method: http.MethodPost, path: "/api/storage/cleanup", body: []byte(`{}`)},
		{name: "system reclaim", method: http.MethodPost, path: "/api/system/reclaim", body: []byte(`{"target":"memory"}`)},
		{name: "block page config", method: http.MethodPut, path: "/api/block-pages/config", body: []byte(`{"template_id":"minimal"}`)},
		{name: "block page upload", method: http.MethodPost, path: "/api/block-pages/upload", body: []byte(`{}`)},
		{name: "block page delete custom", method: http.MethodDelete, path: "/api/block-pages/custom", body: nil},
		{name: "backup restore", method: http.MethodPost, path: "/api/backup/restore", body: []byte(`{}`)},
		{name: "nginx import", method: http.MethodPost, path: "/api/nginx/import", body: []byte(`{}`)},
	}

	for _, tc := range writeCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := perform(router, tc.method, tc.path, readerToken, tc.body)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("expected readonly write to be forbidden, got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRouterPrometheusMetricsArePrivateByDefault(t *testing.T) {
	router, _, readerToken := newAuthzTestRouter(t)

	publicMetrics := perform(router, http.MethodGet, "/metrics", "", nil)
	if publicMetrics.Code != http.StatusNotFound {
		t.Fatalf("expected public /metrics to be disabled by default, got %d: %s", publicMetrics.Code, publicMetrics.Body.String())
	}

	privateMetricsWithoutToken := perform(router, http.MethodGet, "/api/metrics", "", nil)
	if privateMetricsWithoutToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected /api/metrics to require bearer token, got %d: %s", privateMetricsWithoutToken.Code, privateMetricsWithoutToken.Body.String())
	}

	privateMetrics := perform(router, http.MethodGet, "/api/metrics", readerToken, nil)
	if privateMetrics.Code != http.StatusOK {
		t.Fatalf("expected readonly token to read /api/metrics, got %d: %s", privateMetrics.Code, privateMetrics.Body.String())
	}
	if got := privateMetrics.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("unexpected metrics content type %q", got)
	}
}

func TestRouterPrometheusMetricsCanBeExplicitlyPublic(t *testing.T) {
	router, _, _ := newAuthzTestRouterWithConfig(t, func(cfg *config.Config) {
		cfg.Monitor.Prometheus.Enabled = true
		cfg.Monitor.Prometheus.Public = true
		cfg.Monitor.Prometheus.Path = "/metrics"
	})

	recorder := perform(router, http.MethodGet, "/metrics", "", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected explicitly public /metrics to be readable, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("unexpected metrics content type %q", got)
	}
}

func TestRouterLoginCAPTCHAIsEnabledByDefault(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)

	options := perform(router, http.MethodGet, "/api/auth/login-options", "", nil)
	if options.Code != http.StatusOK {
		t.Fatalf("expected public login options, got %d: %s", options.Code, options.Body.String())
	}
	var loginOptions struct {
		Data struct {
			CAPTCHA struct {
				Enabled bool `json:"enabled"`
			} `json:"captcha"`
		} `json:"data"`
	}
	if err := json.NewDecoder(options.Body).Decode(&loginOptions); err != nil {
		t.Fatalf("decode login options: %v", err)
	}
	if !loginOptions.Data.CAPTCHA.Enabled {
		t.Fatal("expected login captcha to be enabled by default")
	}

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin-password"})
	recorder := perform(router, http.MethodPost, "/api/auth/login", "", body)
	if recorder.Code != http.StatusUnauthorized || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected missing captcha to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterSliderCAPTCHARequiresSliderProof(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = true
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	createAuthzUser(t, store, "admin-id", "admin", "admin-password", "admin")
	router := NewRouter(Options{Config: &cfg, ConfigPath: configPath, Store: store, Secret: "router-slider-test-secret"})

	pow := solveLoginCAPTCHA(t, router)
	body, _ := json.Marshal(map[string]any{"username": "admin", "password": "admin-password", "captcha": pow})
	recorder := perform(router, http.MethodPost, "/api/auth/login", "", body)
	if recorder.Code != http.StatusUnauthorized || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected missing slider proof to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterSliderCAPTCHADoesNotIssuePowByDefault(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = false
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	createAuthzUser(t, store, "admin-id", "admin", "admin-password", "admin")
	router := NewRouter(Options{Config: &cfg, ConfigPath: configPath, Store: store, Secret: "router-slider-no-pow-test-secret"})

	recorder := perform(router, http.MethodPost, "/api/auth/captcha", "", []byte(`{}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected slider captcha challenge, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Enabled   bool `json:"enabled"`
			Challenge *struct {
				Challenge string `json:"challenge"`
			} `json:"challenge"`
			Slider *struct {
				Token string `json:"token"`
				Image string `json:"image"`
			} `json:"slider"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode slider captcha response: %v", err)
	}
	if !envelope.Data.Enabled {
		t.Fatal("expected captcha to be enabled")
	}
	if envelope.Data.Challenge != nil && envelope.Data.Challenge.Challenge != "" {
		t.Fatalf("default slider captcha should not issue PoW challenge, got %+v", envelope.Data.Challenge)
	}
	if envelope.Data.Slider == nil || envelope.Data.Slider.Token == "" || envelope.Data.Slider.Image == "" {
		t.Fatalf("expected real slider challenge, got %+v", envelope.Data.Slider)
	}
}

func TestRouterLoginCAPTCHAVerifySliderIssuesOneTimeReceipt(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = false
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	secret := "router-slider-verify-test-secret"
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	createAuthzUser(t, store, "admin-id", "admin", "admin-password", "admin")
	router := NewRouter(Options{Config: &cfg, ConfigPath: configPath, Store: store, Secret: secret})

	challenge := requestSliderLoginCAPTCHA(t, router, []byte(`{}`))
	validX := findValidSliderX(t, cfg, secret, challenge)
	validTrack := sliderTrackForTest(validX, challenge.MinDragMS+50)
	invalid, _ := json.Marshal(map[string]any{
		"mode": "slider",
		"slider": map[string]any{
			"token":   challenge.Token,
			"x":       0,
			"drag_ms": challenge.MinDragMS + 50,
			"track":   sliderTrackForTest(0, challenge.MinDragMS+50),
		},
	})
	recorder := perform(router, http.MethodPost, "/api/auth/captcha/verify", "", invalid)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected bad slider x to fail, got %d: %s", recorder.Code, recorder.Body.String())
	}

	rawLogin, _ := json.Marshal(map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha": map[string]any{
			"mode": "slider",
			"slider": map[string]any{
				"token":   challenge.Token,
				"x":       validX,
				"drag_ms": challenge.MinDragMS + 50,
			},
		},
	})
	recorder = perform(router, http.MethodPost, "/api/auth/login", "", rawLogin)
	if recorder.Code != http.StatusUnauthorized || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected raw slider proof without behavior track to fail before receipt, got %d: %s", recorder.Code, recorder.Body.String())
	}

	rawLoginWithTrack, _ := json.Marshal(map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha": map[string]any{
			"mode": "slider",
			"slider": map[string]any{
				"token":   challenge.Token,
				"x":       validX,
				"drag_ms": challenge.MinDragMS + 50,
				"track":   validTrack,
			},
		},
	})
	recorder = perform(router, http.MethodPost, "/api/auth/login", "", rawLoginWithTrack)
	if recorder.Code != http.StatusUnauthorized || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected raw slider proof login to require receipt, got %d: %s", recorder.Code, recorder.Body.String())
	}

	valid, _ := json.Marshal(map[string]any{
		"mode": "slider",
		"slider": map[string]any{
			"token":   challenge.Token,
			"x":       validX,
			"drag_ms": challenge.MinDragMS + 50,
			"track":   validTrack,
		},
	})
	recorder = perform(router, http.MethodPost, "/api/auth/captcha/verify", "", valid)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected valid slider proof to issue receipt, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var verified struct {
		Data struct {
			Receipt string `json:"receipt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&verified); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if verified.Data.Receipt == "" {
		t.Fatal("verify response did not include a receipt")
	}

	reverify := perform(router, http.MethodPost, "/api/auth/captcha/verify", "", valid)
	if reverify.Code != http.StatusUnauthorized {
		t.Fatalf("slider token should be consumed after issuing receipt, got %d: %s", reverify.Code, reverify.Body.String())
	}

	loginBody, _ := json.Marshal(map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha":  map[string]any{"mode": "slider", "receipt": verified.Data.Receipt},
	})
	recorder = perform(router, http.MethodPost, "/api/auth/login", "", loginBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected receipt-backed login to succeed, got %d: %s", recorder.Code, recorder.Body.String())
	}

	reuse := perform(router, http.MethodPost, "/api/auth/login", "", loginBody)
	if reuse.Code != http.StatusUnauthorized || !bytes.Contains(reuse.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("receipt should be one-time, got %d: %s", reuse.Code, reuse.Body.String())
	}
}

func TestRouterLoginCAPTCHASliderVerifyLocksAfterFailures(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = false
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	secret := "router-slider-lock-test-secret"
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	router := NewRouter(Options{Config: &cfg, ConfigPath: configPath, Store: store, Secret: secret})

	challenge := requestSliderLoginCAPTCHA(t, router, []byte(`{}`))
	validX := findValidSliderX(t, cfg, secret, challenge)
	validTrack := sliderTrackForTest(validX, challenge.MinDragMS+50)
	badX := 0
	if validX == 0 {
		badX = challenge.TrackWidth
	}
	badTrack := sliderTrackForTest(badX, challenge.MinDragMS+50)
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(map[string]any{
			"mode": "slider",
			"slider": map[string]any{
				"token":   challenge.Token,
				"x":       badX,
				"drag_ms": challenge.MinDragMS + 50,
				"track":   badTrack,
			},
		})
		recorder := perform(router, http.MethodPost, "/api/auth/captcha/verify", "", body)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected bad slider attempt %d to fail, got %d: %s", i+1, recorder.Code, recorder.Body.String())
		}
	}
	valid, _ := json.Marshal(map[string]any{
		"mode": "slider",
		"slider": map[string]any{
			"token":   challenge.Token,
			"x":       validX,
			"drag_ms": challenge.MinDragMS + 50,
			"track":   validTrack,
		},
	})
	recorder := perform(router, http.MethodPost, "/api/auth/captcha/verify", "", valid)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("locked slider token should not issue receipt after failures, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterLoginCAPTCHAPowModeCanVerifyWhenConfiguredForSlider(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Mode = "slider"
	cfg.Console.Login.CAPTCHA.Slider.PowEnabled = false
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	router := NewRouter(Options{Config: &cfg, ConfigPath: configPath, Store: store, Secret: "router-pow-override-test-secret"})

	payload := solveLoginCAPTCHAWithRequest(t, router, []byte(`{"mode":"pow"}`))
	if payload == nil || payload["mode"] != "pow" {
		t.Fatalf("expected a pow payload, got %#v", payload)
	}
	body, _ := json.Marshal(payload)
	recorder := perform(router, http.MethodPost, "/api/auth/captcha/verify", "", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected pow payload to verify against slider config, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterRefreshesBearerToken(t *testing.T) {
	router, adminToken, _ := newAuthzTestRouter(t)

	withoutToken := perform(router, http.MethodPost, "/api/auth/refresh", "", []byte(`{}`))
	if withoutToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected refresh without bearer token to be unauthorized, got %d: %s", withoutToken.Code, withoutToken.Body.String())
	}

	refreshed := perform(router, http.MethodPost, "/api/auth/refresh", adminToken, []byte(`{}`))
	if refreshed.Code != http.StatusOK {
		t.Fatalf("expected refresh to succeed, got %d: %s", refreshed.Code, refreshed.Body.String())
	}
	var envelope struct {
		Data struct {
			Token string `json:"token"`
			User  struct {
				Username string `json:"username"`
				Role     string `json:"role"`
			} `json:"user"`
		} `json:"data"`
	}
	if err := json.NewDecoder(refreshed.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if envelope.Data.Token == "" {
		t.Fatal("refresh response did not include token")
	}
	if envelope.Data.Token == adminToken {
		t.Fatal("refresh returned the same token; expected a rotated token id")
	}
	if envelope.Data.User.Username != "admin" || envelope.Data.User.Role != "admin" {
		t.Fatalf("unexpected refresh user: %+v", envelope.Data.User)
	}

	system := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil)
	if system.Code != http.StatusOK {
		t.Fatalf("refreshed token should access protected API, got %d: %s", system.Code, system.Body.String())
	}

	oldToken := perform(router, http.MethodGet, "/api/system", adminToken, nil)
	if oldToken.Code != http.StatusUnauthorized {
		t.Fatalf("old token should be revoked after refresh, got %d: %s", oldToken.Code, oldToken.Body.String())
	}
}

func TestRouterLogoutRevokesBearerToken(t *testing.T) {
	router, adminToken, _ := newAuthzTestRouter(t)

	withoutToken := perform(router, http.MethodPost, "/api/auth/logout", "", []byte(`{}`))
	if withoutToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected logout without bearer token to be unauthorized, got %d: %s", withoutToken.Code, withoutToken.Body.String())
	}

	logout := perform(router, http.MethodPost, "/api/auth/logout", adminToken, []byte(`{}`))
	if logout.Code != http.StatusOK {
		t.Fatalf("expected logout to succeed, got %d: %s", logout.Code, logout.Body.String())
	}

	system := perform(router, http.MethodGet, "/api/system", adminToken, nil)
	if system.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token should be rejected, got %d: %s", system.Code, system.Body.String())
	}
}

func TestRouterUserUpdateRevokesExistingUserSessions(t *testing.T) {
	router, adminToken, readerToken := newAuthzTestRouter(t)

	before := perform(router, http.MethodGet, "/api/system", readerToken, nil)
	if before.Code != http.StatusOK {
		t.Fatalf("reader token should start active, got %d: %s", before.Code, before.Body.String())
	}

	update := perform(router, http.MethodPut, "/api/users/reader-id", adminToken, []byte(`{"password":"new-reader-password","role":"readonly"}`))
	if update.Code != http.StatusOK {
		t.Fatalf("expected admin to update reader, got %d: %s", update.Code, update.Body.String())
	}

	after := perform(router, http.MethodGet, "/api/system", readerToken, nil)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("reader token should be revoked after sensitive user update, got %d: %s", after.Code, after.Body.String())
	}
}

func newAuthzTestRouter(t *testing.T) (http.Handler, string, string) {
	return newAuthzTestRouterWithConfig(t, func(cfg *config.Config) {
		cfg.Monitor.Prometheus.Enabled = true
		cfg.Monitor.Prometheus.Public = false
	})
}

func newAuthzTestRouterWithConfig(t *testing.T, mutate func(*config.Config)) (http.Handler, string, string) {
	t.Helper()
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	cfg.APISec.Audit.Enabled = false
	cfg.Storage.SQLite.Path = filepath.Join(tempDir, "cheesewaf.db")
	cfg.Logging.Output.File.Path = filepath.Join(tempDir, "access.log")
	if mutate != nil {
		mutate(&cfg)
	}
	configPath := filepath.Join(tempDir, "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	store, err := storage.OpenSQLite(cfg.Storage.SQLite.Path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	createAuthzUser(t, store, "admin-id", "admin", "admin-password", "admin")
	createAuthzUser(t, store, "reader-id", "reader", "reader-password", "readonly")

	router := NewRouter(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		Store:      store,
		Secret:     "router-authz-test-secret",
	})
	adminToken := loginAuthzUser(t, router, "admin", "admin-password")
	readerToken := loginAuthzUser(t, router, "reader", "reader-password")
	return router, adminToken, readerToken
}

func createAuthzUser(t *testing.T, store storage.Store, id, username, password, role string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := store.CreateUser(context.Background(), &storage.User{
		ID:           id,
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
	}); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
}

func loginAuthzUser(t *testing.T, router http.Handler, username, password string) string {
	t.Helper()
	bodyPayload := map[string]any{"username": username, "password": password}
	if payload := solveLoginCAPTCHA(t, router); payload != nil {
		bodyPayload["captcha"] = payload
	}
	body, err := json.Marshal(bodyPayload)
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	recorder := perform(router, http.MethodPost, "/api/auth/login", "", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login %s returned %d: %s", username, recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if envelope.Data.Token == "" {
		t.Fatal("login response did not include token")
	}
	return envelope.Data.Token
}

func solveLoginCAPTCHA(t *testing.T, router http.Handler) map[string]any {
	return solveLoginCAPTCHAWithRequest(t, router, []byte(`{}`))
}

func solveLoginCAPTCHAWithRequest(t *testing.T, router http.Handler, requestBody []byte) map[string]any {
	t.Helper()
	recorder := perform(router, http.MethodPost, "/api/auth/captcha", "", requestBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("captcha challenge returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Enabled   bool   `json:"enabled"`
			Mode      string `json:"mode"`
			Challenge struct {
				Algorithm string `json:"algorithm"`
				Challenge string `json:"challenge"`
				MaxNumber int    `json:"max_number"`
				Salt      string `json:"salt"`
				Signature string `json:"signature"`
			} `json:"challenge"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode captcha challenge: %v", err)
	}
	if !envelope.Data.Enabled {
		return nil
	}
	challenge := envelope.Data.Challenge
	if challenge.Challenge == "" {
		return nil
	}
	for i := 0; i <= challenge.MaxNumber; i++ {
		if captcha.Hash(challenge.Salt, i) == challenge.Challenge {
			payload := map[string]any{
				"algorithm": challenge.Algorithm,
				"challenge": challenge.Challenge,
				"number":    i,
				"salt":      challenge.Salt,
				"signature": challenge.Signature,
			}
			if envelope.Data.Mode != "" {
				payload["mode"] = envelope.Data.Mode
			}
			return payload
		}
	}
	t.Fatalf("failed to solve login captcha challenge")
	return nil
}

type sliderLoginCAPTCHAForTest struct {
	Token      string
	TrackWidth int
	MinDragMS  int
}

func requestSliderLoginCAPTCHA(t *testing.T, router http.Handler, requestBody []byte) sliderLoginCAPTCHAForTest {
	t.Helper()
	recorder := perform(router, http.MethodPost, "/api/auth/captcha", "", requestBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("slider captcha challenge returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Slider struct {
				Token      string `json:"token"`
				TrackWidth int    `json:"track_width"`
				MinDragMS  int    `json:"min_drag_ms"`
			} `json:"slider"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode slider captcha challenge: %v", err)
	}
	if envelope.Data.Slider.Token == "" || envelope.Data.Slider.TrackWidth <= 0 {
		t.Fatalf("expected slider challenge, got %+v", envelope.Data.Slider)
	}
	return sliderLoginCAPTCHAForTest{
		Token:      envelope.Data.Slider.Token,
		TrackWidth: envelope.Data.Slider.TrackWidth,
		MinDragMS:  envelope.Data.Slider.MinDragMS,
	}
}

func findValidSliderX(t *testing.T, cfg config.Config, secret string, challenge sliderLoginCAPTCHAForTest) int {
	t.Helper()
	for x := 0; x <= challenge.TrackWidth; x++ {
		if captcha.VerifySlider(captcha.SliderOptions{
			Secret:    secret,
			Purpose:   "admin-login-slider",
			ClientKey: "192.0.2.1\n",
			Path:      "admin-login",
			TTL:       cfg.Console.Login.CAPTCHA.TTL,
			Width:     cfg.Console.Login.CAPTCHA.Slider.Width,
			Height:    cfg.Console.Login.CAPTCHA.Slider.Height,
			PieceSize: cfg.Console.Login.CAPTCHA.Slider.PieceSize,
			Tolerance: cfg.Console.Login.CAPTCHA.Slider.Tolerance,
			MinDrag:   cfg.Console.Login.CAPTCHA.Slider.MinDrag,
		}, captcha.SliderPayload{
			Token:  challenge.Token,
			X:      x,
			DragMS: challenge.MinDragMS + 50,
		}) {
			return x
		}
	}
	t.Fatalf("failed to find valid slider x within track width %d", challenge.TrackWidth)
	return -1
}

func sliderTrackForTest(finalX, dragMS int) string {
	midX := finalX / 2
	return fmt.Sprintf(
		`[{"x":0,"y":20,"t":0,"type":"down"},{"x":%d,"y":21,"t":%d,"type":"move"},{"x":%d,"y":22,"t":%d,"type":"up"}]`,
		midX,
		dragMS/2,
		finalX,
		dragMS,
	)
}

func perform(router http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}
