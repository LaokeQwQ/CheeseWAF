package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
		{name: "backup export", method: http.MethodPost, path: "/api/backup/export"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := perform(router, tc.method, tc.path, "", nil)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 without bearer token, got %d: %s", recorder.Code, recorder.Body.String())
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
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
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
