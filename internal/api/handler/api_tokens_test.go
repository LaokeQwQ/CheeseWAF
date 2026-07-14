package handler

import (
	"bytes"
	"context"
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
	persisted, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load persisted config: %v", err)
	}
	if len(persisted.APISec.ManagementAPI.Tokens) != 1 || persisted.APISec.ManagementAPI.Tokens[0].ID != created.ID {
		t.Fatalf("created token was not persisted: %+v", persisted.APISec.ManagementAPI.Tokens)
	}

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
	persisted, err = config.Load(configPath)
	if err != nil {
		t.Fatalf("reload revoked config: %v", err)
	}
	if persisted.APISec.ManagementAPI.Tokens[0].Enabled || persisted.APISec.ManagementAPI.Tokens[0].RevokedAt.IsZero() {
		t.Fatalf("revoked token was not persisted: %+v", persisted.APISec.ManagementAPI.Tokens[0])
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
