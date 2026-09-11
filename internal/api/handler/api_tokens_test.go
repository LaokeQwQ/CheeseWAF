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
	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
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

func TestCreateManagementAPITokenUsesSafeDefaultAndRejectsOverlongLifetime(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		body       string
		wantStatus int
		check      func(*testing.T, config.ManagementAPITokenConfig)
	}{
		{name: "default", body: "{\"name\":\"default\",\"scopes\":[\"read:system\"]}", wantStatus: http.StatusOK, check: func(t *testing.T, item config.ManagementAPITokenConfig) {
			if item.NeverExpire || !item.ExpiresAt.Equal(now.Add(tokens.DefaultTTL)) {
				t.Fatalf("default lifetime = never=%v expires=%v", item.NeverExpire, item.ExpiresAt)
			}
		}},
		{name: "overlong", body: "{\"name\":\"overlong\",\"scopes\":[\"read:system\"],\"ttl\":\"366d\"}", wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.APISec.ManagementAPI.Enabled = true
			h := New(Options{Config: &cfg})
			h.now = func() time.Time { return now }
			recorder := httptest.NewRecorder()
			h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", tc.body))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), tc.wantStatus)
			}
			if tc.check != nil {
				if len(cfg.APISec.ManagementAPI.Tokens) != 1 {
					t.Fatalf("token count=%d", len(cfg.APISec.ManagementAPI.Tokens))
				}
				tc.check(t, cfg.APISec.ManagementAPI.Tokens[0])
			}
		})
	}
}

func TestCreateManagementAPITokenNeverExpireNeedsExplicitConfirmation(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	h := New(Options{Config: &cfg})
	h.now = func() time.Time { return now }
	without := httptest.NewRecorder()
	h.CreateManagementAPIToken(without, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", "{\"name\":\"forever\",\"scopes\":[\"read:system\"],\"never_expire\":true}"))
	if without.Code != http.StatusBadRequest || !strings.Contains(without.Body.String(), "API_TOKEN_CONFIRMATION_REQUIRED") {
		t.Fatalf("missing confirmation status=%d body=%s", without.Code, without.Body.String())
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
		t.Fatalf("unconfirmed request mutated config: %+v", cfg.APISec.ManagementAPI.Tokens)
	}
	confirmed := httptest.NewRecorder()
	h.CreateManagementAPIToken(confirmed, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", "{\"name\":\"forever\",\"scopes\":[\"read:system\"],\"never_expire\":true,\"confirm_never_expire\":true,\"confirmation_id\":\"confirm-1\"}"))
	if confirmed.Code != http.StatusNotImplemented || !strings.Contains(confirmed.Body.String(), "API_TOKEN_CONFIRMATION_UNAVAILABLE") {
		t.Fatalf("confirmation-unavailable status=%d body=%s", confirmed.Code, confirmed.Body.String())
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
		t.Fatalf("unavailable confirmation mutated config: %+v", cfg.APISec.ManagementAPI.Tokens)
	}
}

func TestCreateManagementAPITokenNeverExpireConfirmationIDCannotReplay(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	h := New(Options{Config: &cfg})
	h.now = func() time.Time { return now }
	used := false
	h.managementTokenConfirmationVerifier = func(_ *http.Request, confirmation ManagementTokenConfirmation, _ time.Time) error {
		if confirmation.ConfirmationID != "confirm-replay" {
			return fmt.Errorf("unexpected confirmation id")
		}
		if used {
			return errManagementAPITokenConfirmationReplay
		}
		used = true
		return nil
	}
	body := `{"name":"forever","scopes":["read:system"],"never_expire":true,"confirm_never_expire":true,"confirmation_id":"confirm-replay"}`
	first := httptest.NewRecorder()
	h.CreateManagementAPIToken(first, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", body))
	if first.Code != http.StatusOK {
		t.Fatalf("first confirmed create status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	h.CreateManagementAPIToken(second, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", body))
	if second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "API_TOKEN_CONFIRMATION_REPLAY") {
		t.Fatalf("replayed confirmation status=%d body=%s", second.Code, second.Body.String())
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 1 {
		t.Fatalf("replay created another token: %+v", cfg.APISec.ManagementAPI.Tokens)
	}
}

func TestManagementAPITokenCleanupHonorsCoalescedDeadline(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	old := now.Add(-time.Minute)
	cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
		ID: "inactive", Name: "inactive", Prefix: "cwapi_inactive", Hash: middleware.HashManagementAPIToken("cwapi_inactive-secret"),
		Scopes: []string{"read:system"}, Enabled: true, CreatedAt: old, LastUsedAt: old, ExpiresAt: now.Add(-time.Second),
	}}
	h := New(Options{Config: &cfg})
	if removed, err := h.CleanupManagementAPITokens(now); err != nil || removed != 0 {
		t.Fatalf("cleanup before deadline removed=%d err=%v", removed, err)
	}
	if due := h.NextManagementAPITokenCleanupAt(); due.IsZero() {
		t.Fatal("cleanup deadline was not initialized")
	} else if !due.After(now) {
		t.Fatalf("new token deadline=%v should be after now=%v", due, now)
	}
	if removed, err := h.CleanupManagementAPITokens(now.Add(tokens.CleanupDelay)); err != nil || removed != 1 {
		t.Fatalf("cleanup at deadline removed=%d err=%v", removed, err)
	}
}

func TestManagementAPITokenCleanupRemovesExpiredAndInactiveWithAudit(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	old := now.Add(-tokens.InactivityTTL - time.Hour)
	cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
		ID: "inactive", Name: "inactive", Prefix: "cwapi_inactive", Hash: middleware.HashManagementAPIToken("cwapi_inactive-secret"),
		Scopes: []string{"read:system"}, Enabled: true, CreatedAt: old, LastUsedAt: old, NeverExpire: true,
	}}
	h := New(Options{Config: &cfg, Auditor: middleware.NewAuditor(auditPath)})
	h.now = func() time.Time { return now }
	removed, err := h.CleanupManagementAPITokens(now)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup removed=%d err=%v", removed, err)
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
		t.Fatalf("inactive token remains: %+v", cfg.APISec.ManagementAPI.Tokens)
	}
	entries, err := h.Auditor.Query(10)
	if err != nil || len(entries) != 1 || entries[0].Subject != "api-token:inactive" || !strings.Contains(entries[0].Message, "inactive") {
		t.Fatalf("cleanup audit=%+v err=%v", entries, err)
	}
}

func TestCreateManagementAPITokenPreservesDisplayTextSpaces(t *testing.T) {
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	h := New(Options{Config: &cfg})
	recorder := httptest.NewRecorder()
	body := "{\"name\":\"  deploy bot  \",\"notes\":\"  owned by ops  \",\"scopes\":[\"read:system\"]}"
	h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), http.StatusOK)
	}
	if got := cfg.APISec.ManagementAPI.Tokens[0]; got.Name != "  deploy bot  " || got.Notes != "  owned by ops  " {
		t.Fatalf("display text was rewritten: name=%q notes=%q", got.Name, got.Notes)
	}
}

func TestCreateManagementAPITokenRejectsNonCanonicalScopes(t *testing.T) {
	for _, scope := range []string{" read:system", "read:system ", "read:\tsystem", "read:system\u200b", "read:system\x00"} {
		t.Run(scope, func(t *testing.T) {
			cfg := config.Default()
			cfg.APISec.ManagementAPI.Enabled = true
			h := New(Options{Config: &cfg})
			recorder := httptest.NewRecorder()
			body := fmt.Sprintf("{\"name\":\"deploy\",\"scopes\":[%q]}", scope)
			h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), http.StatusBadRequest)
			}
			if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
				t.Fatalf("invalid scope created token: %+v", cfg.APISec.ManagementAPI.Tokens)
			}
		})
	}
}

func TestCreateManagementAPITokenRejectsNonCanonicalConfirmationID(t *testing.T) {
	for _, id := range []string{" confirm-1", "confirm-1 ", "confirm-\t1", "confirm-1\u200b", "confirm-1\x00"} {
		t.Run(id, func(t *testing.T) {
			cfg := config.Default()
			cfg.APISec.ManagementAPI.Enabled = true
			h := New(Options{Config: &cfg})
			h.managementTokenConfirmationVerifier = func(_ *http.Request, _ ManagementTokenConfirmation, _ time.Time) error { return nil }
			recorder := httptest.NewRecorder()
			body := fmt.Sprintf("{\"name\":\"forever\",\"scopes\":[\"read:system\"],\"never_expire\":true,\"confirm_never_expire\":true,\"confirmation_id\":%q}", id)
			h.CreateManagementAPIToken(recorder, managementAPITokenRequest(http.MethodPost, "/api/system/api-tokens", body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), http.StatusBadRequest)
			}
			if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
				t.Fatalf("invalid confirmation id created token: %+v", cfg.APISec.ManagementAPI.Tokens)
			}
		})
	}
}

func TestRevokeManagementAPITokenRejectsNonCanonicalID(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.Default()
	cfg.APISec.ManagementAPI.Enabled = true
	cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
		ID: "token-1", Name: "deploy", Prefix: "cwapi_token-1", Hash: middleware.HashManagementAPIToken("cwapi_token-1-secret"),
		Scopes: []string{"read:system"}, Enabled: true, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
	}}
	h := New(Options{Config: &cfg})
	for _, id := range []string{" token-1", "token-1 ", "token-\t1", "token-1\u200b", "token-1\x00"} {
		t.Run(id, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := withManagementAPITokenID(managementAPITokenRequest(http.MethodDelete, "/api/system/api-tokens/token-1", ""), id)
			h.RevokeManagementAPIToken(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), http.StatusBadRequest)
			}
		})
	}
	if !cfg.APISec.ManagementAPI.Tokens[0].Enabled || !cfg.APISec.ManagementAPI.Tokens[0].RevokedAt.IsZero() {
		t.Fatalf("invalid id changed token state: %+v", cfg.APISec.ManagementAPI.Tokens[0])
	}
}

func TestPermissionMatchesRejectsNonCanonicalSelectors(t *testing.T) {
	for _, tc := range []struct{ permission, required string }{
		{permission: " read:system", required: "read:system"},
		{permission: "read:system ", required: "read:system"},
		{permission: "read:system", required: " read:system"},
		{permission: "read:\tsystem", required: "read:system"},
		{permission: "read:system\u200b", required: "read:system"},
	} {
		if permissionMatches(tc.permission, tc.required) {
			t.Fatalf("permissionMatches(%q, %q) accepted non-canonical selector", tc.permission, tc.required)
		}
	}
}
