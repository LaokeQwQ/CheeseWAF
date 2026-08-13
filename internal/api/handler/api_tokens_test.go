package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/go-chi/chi/v5"
)

func TestManagementAPITokenCreateAndRevokePersistTransactionally(t *testing.T) {
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	h := New(Options{Config: &cfg, ConfigPath: configPath})
	now := time.Date(2031, time.March, 4, 5, 6, 7, 0, time.UTC)
	h.now = func() time.Time { return now }

	createRecorder := httptest.NewRecorder()
	createRequest := managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", `{"name":"deploy","scopes":["read:system"],"ttl":"1h"}`)
	h.CreateManagementAPIToken(createRecorder, createRequest)
	if createRecorder.Code != http.StatusOK {
		t.Fatalf("create token: code=%d body=%s", createRecorder.Code, createRecorder.Body.String())
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 1 {
		t.Fatalf("live config token count = %d, want 1", len(cfg.APISec.ManagementAPI.Tokens))
	}
	created := cfg.APISec.ManagementAPI.Tokens[0]
	if created.Name != "deploy" || created.Hash == "" || created.ExpiresAt.IsZero() {
		t.Fatalf("unexpected created token: %+v", created)
	}
	if !strings.HasPrefix(created.Hash, "sha256:") {
		t.Fatalf("created token hash = %q, want sha256", created.Hash)
	}
	if !created.CreatedAt.Equal(now) || !created.UpdatedAt.Equal(now) || !created.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("created token timestamps = created:%v updated:%v expires:%v, want %v/%v/%v", created.CreatedAt, created.UpdatedAt, created.ExpiresAt, now, now, now.Add(time.Hour))
	}
	persisted, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if len(persisted.APISec.ManagementAPI.Tokens) != 1 || persisted.APISec.ManagementAPI.Tokens[0].ID != created.ID {
		t.Fatalf("created token was not persisted: %+v", persisted.APISec.ManagementAPI.Tokens)
	}

	now = now.Add(30 * time.Minute)
	revokeRecorder := httptest.NewRecorder()
	revokeRequest := managementAPITokenRequest(http.MethodDelete, "/api/system/api-tokens/"+created.ID, "")
	revokeRequest = withManagementAPITokenID(revokeRequest, created.ID)
	h.RevokeManagementAPIToken(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("revoke token: code=%d body=%s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
	if cfg.APISec.ManagementAPI.Tokens[0].Enabled || cfg.APISec.ManagementAPI.Tokens[0].RevokedAt.IsZero() {
		t.Fatalf("live token was not revoked: %+v", cfg.APISec.ManagementAPI.Tokens[0])
	}
	if !cfg.APISec.ManagementAPI.Tokens[0].RevokedAt.Equal(now) || !cfg.APISec.ManagementAPI.Tokens[0].UpdatedAt.Equal(now) {
		t.Fatalf("revoked token timestamps = revoked:%v updated:%v, want %v", cfg.APISec.ManagementAPI.Tokens[0].RevokedAt, cfg.APISec.ManagementAPI.Tokens[0].UpdatedAt, now)
	}
	persisted, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("reload revoked config: %v", err)
	}
	if persisted.APISec.ManagementAPI.Tokens[0].Enabled || persisted.APISec.ManagementAPI.Tokens[0].RevokedAt.IsZero() {
		t.Fatalf("revoked token was not persisted: %+v", persisted.APISec.ManagementAPI.Tokens[0])
	}
}

func TestManagementAPITokenAuthenticationDoesNotHoldConfigLockAcrossHandler(t *testing.T) {
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	raw := "cwapi_write_system_fixture"
	cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
		ID: "write-system", Name: "write system", Prefix: "cwapi_write_system",
		Hash: middleware.HashManagementAPIToken(raw), Scopes: []string{"write:system"}, Enabled: true,
	}}
	h := New(Options{Config: &cfg})
	wrapped := middleware.ManagementAPIOrSessionMiddleware(nil, nil, h.AuthenticateManagementAPIToken)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := h.commitConfigMutation(func(*config.Config) error { return nil }, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPut, "/api/system", nil)
	req.Header.Set("Authorization", "Bearer "+raw)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		wrapped.ServeHTTP(recorder, req)
		done <- recorder
	}()
	select {
	case recorder := <-done:
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("write handler returned %d: %s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("management-token write handler deadlocked on the configuration lock")
	}
}

func TestCreateManagementAPITokenRejectsActiveCapacity(t *testing.T) {
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	for idx := 0; idx < config.MaxActiveManagementAPITokens; idx++ {
		raw := fmt.Sprintf("cwapi_capacity_%04d_secret", idx)
		cfg.APISec.ManagementAPI.Tokens = append(cfg.APISec.ManagementAPI.Tokens, config.ManagementAPITokenConfig{
			ID: fmt.Sprintf("token-%d", idx), Name: fmt.Sprintf("token-%d", idx), Prefix: raw[:18],
			Hash: middleware.HashManagementAPIToken(raw), Scopes: []string{"read:system"}, Enabled: true,
		})
	}
	h := New(Options{Config: &cfg})
	recorder := httptest.NewRecorder()
	h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", `{"name":"overflow","scopes":["read:system"]}`))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "API_TOKEN_CAPACITY") {
		t.Fatalf("expected capacity error, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := len(cfg.APISec.ManagementAPI.Tokens); got != config.MaxActiveManagementAPITokens {
		t.Fatalf("capacity failure mutated tokens: %d", got)
	}
}

func TestCreateManagementAPITokenValidationFailureDoesNotMutateOrPersist(t *testing.T) {
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
		ID: "broken", Name: "broken", Hash: "invalid", Scopes: []string{"read:system"}, Enabled: true,
	}}
	h := New(Options{Config: &cfg, ConfigPath: configPath})

	recorder := httptest.NewRecorder()
	h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", `{"name":"new","scopes":["read:system"]}`))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "API_TOKEN_INVALID") {
		t.Fatalf("expected validation error, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 1 || cfg.APISec.ManagementAPI.Tokens[0].ID != "broken" {
		t.Fatalf("validation failure mutated live config: %+v", cfg.APISec.ManagementAPI.Tokens)
	}
	persisted, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if len(persisted.APISec.ManagementAPI.Tokens) != 0 {
		t.Fatalf("validation failure changed disk config: %+v", persisted.APISec.ManagementAPI.Tokens)
	}
}

func TestManagementAPITokenPersistenceFailureRollsBackCreateAndRevoke(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		cfg := config.Default()
		cfg.APISec.ManagementAPI.Enabled = true
		h := New(Options{Config: &cfg, ConfigPath: blockedManagementAPITokenConfigPath(t)})
		recorder := httptest.NewRecorder()
		h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", `{"name":"new","scopes":["read:system"]}`))
		if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "CONFIG_SAVE_ERROR") {
			t.Fatalf("expected persistence error, code=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
			t.Fatalf("failed create mutated live config: %+v", cfg.APISec.ManagementAPI.Tokens)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		cfg := config.Default()
		cfg.APISec.ManagementAPI.Enabled = true
		createdAt := time.Now().UTC().Add(-time.Hour)
		cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
			ID: "token-1", Name: "existing", Prefix: "cw_api_existing", Hash: middleware.HashManagementAPIToken("cw_api_existing-secret"),
			Scopes: []string{"read:system"}, Enabled: true, CreatedAt: createdAt, UpdatedAt: createdAt,
		}}
		h := New(Options{Config: &cfg, ConfigPath: blockedManagementAPITokenConfigPath(t)})
		recorder := httptest.NewRecorder()
		request := withManagementAPITokenID(managementAPITokenRequest(http.MethodDelete, "/api/system/api-tokens/token-1", ""), "token-1")
		h.RevokeManagementAPIToken(recorder, request)
		if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "CONFIG_SAVE_ERROR") {
			t.Fatalf("expected persistence error, code=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if !cfg.APISec.ManagementAPI.Tokens[0].Enabled || !cfg.APISec.ManagementAPI.Tokens[0].RevokedAt.IsZero() || !cfg.APISec.ManagementAPI.Tokens[0].UpdatedAt.Equal(createdAt) {
			t.Fatalf("failed revoke mutated live config: %+v", cfg.APISec.ManagementAPI.Tokens[0])
		}
	})
}

func managementAPITokenRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	claims := &middleware.Claims{Subject: "admin-id", ID: "admin-session", Username: "admin", Role: "admin"}
	return request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, claims))
}

func withManagementAPITokenID(request *http.Request, id string) *http.Request {
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", id)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
}

func blockedManagementAPITokenConfigPath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("create config path blocker: %v", err)
	}
	return filepath.Join(blocker, "cheesewaf.yaml")
}
