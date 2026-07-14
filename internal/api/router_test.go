package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
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
		{name: "threat provider test", method: http.MethodPost, path: "/api/ip/threat-intel/test", body: []byte(`{"endpoint":"https://intel.example.test/feed"}`)},
		{name: "protection policy", method: http.MethodPut, path: "/api/protection/policy", body: []byte(`{}`)},
		{name: "captcha asset upload", method: http.MethodPost, path: "/api/captcha/assets", body: []byte(`{}`)},
		{name: "captcha asset delete", method: http.MethodDelete, path: "/api/captcha/assets/test-id", body: nil},
		{name: "captcha asset config", method: http.MethodPut, path: "/api/captcha/assets/config", body: []byte(`{}`)},
		{name: "captcha asset config test", method: http.MethodPost, path: "/api/captcha/assets/config/test", body: []byte(`{}`)},
		{name: "create site", method: http.MethodPost, path: "/api/sites", body: []byte(`{}`)},
		{name: "delete site", method: http.MethodDelete, path: "/api/sites/default", body: nil},
		{name: "create rule", method: http.MethodPost, path: "/api/rules", body: []byte(`{}`)},
		{name: "delete rule", method: http.MethodDelete, path: "/api/rules/rule-1", body: nil},
		{name: "scheduler tasks", method: http.MethodPut, path: "/api/scheduler/tasks", body: []byte(`{"tasks":[]}`)},
		{name: "edge policy", method: http.MethodPut, path: "/api/edge", body: []byte(`{}`)},
		{name: "ai config", method: http.MethodPut, path: "/api/ai/config", body: []byte(`{}`)},
		{name: "ai model list with override", method: http.MethodPost, path: "/api/ai/models", body: []byte(`{"api_base":"https://api.example.test/v1","api_key":"key"}`)},
		{name: "ai connection test", method: http.MethodPost, path: "/api/ai/test", body: []byte(`{"api_base":"https://api.example.test/v1","api_key":"key","model":"gpt-test"}`)},
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

func TestRouterBotChallengeMetricsRequiresProtectionReadPermission(t *testing.T) {
	router, _, readerToken := newAuthzTestRouter(t)
	withoutToken := perform(router, http.MethodGet, "/api/protection/bot/metrics", "", nil)
	if withoutToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected bot metrics to require authentication, got %d: %s", withoutToken.Code, withoutToken.Body.String())
	}
	withReader := perform(router, http.MethodGet, "/api/protection/bot/metrics?range=24h", readerToken, nil)
	if withReader.Code != http.StatusOK {
		t.Fatalf("expected readonly token to read bot metrics, got %d: %s", withReader.Code, withReader.Body.String())
	}
	invalidRange := perform(router, http.MethodGet, "/api/protection/bot/metrics?range=forever", readerToken, nil)
	if invalidRange.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid range to be rejected, got %d: %s", invalidRange.Code, invalidRange.Body.String())
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

func TestRouterManagementAPITokenLifecycleAndScopes(t *testing.T) {
	router, cfg, _, adminToken, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
	})

	createBody := []byte(`{"name":"readonly automation","scopes":["read:system"],"ttl":"1h"}`)
	created := perform(router, http.MethodPost, "/api/system/api-tokens", adminToken, createBody)
	if created.Code != http.StatusOK {
		t.Fatalf("expected api token creation to succeed, got %d: %s", created.Code, created.Body.String())
	}
	var envelope struct {
		Data struct {
			Token string `json:"token"`
			Item  struct {
				ID     string   `json:"id"`
				Name   string   `json:"name"`
				Scopes []string `json:"scopes"`
				Hash   string   `json:"hash"`
			} `json:"item"`
		} `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode create token response: %v", err)
	}
	if envelope.Data.Token == "" || envelope.Data.Item.ID == "" {
		t.Fatalf("create response must include one-time token and item id: %+v", envelope.Data)
	}
	if envelope.Data.Item.Hash != "" {
		t.Fatalf("create response must not expose persisted token hash: %+v", envelope.Data.Item)
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 1 {
		t.Fatalf("expected one persisted api token, got %+v", cfg.APISec.ManagementAPI.Tokens)
	}
	if cfg.APISec.ManagementAPI.Tokens[0].Hash == "" || cfg.APISec.ManagementAPI.Tokens[0].Hash == envelope.Data.Token {
		t.Fatalf("config must persist only a non-raw hash, got %+v", cfg.APISec.ManagementAPI.Tokens[0])
	}

	read := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("scoped api token should read system config, got %d: %s", read.Code, read.Body.String())
	}
	if cfg.APISec.ManagementAPI.Tokens[0].LastUsedAt.IsZero() {
		t.Fatal("successful api token use should record last_used_at")
	}
	if bytes.Contains(read.Body.Bytes(), []byte(envelope.Data.Token)) || bytes.Contains(read.Body.Bytes(), []byte(cfg.APISec.ManagementAPI.Tokens[0].Hash)) {
		t.Fatalf("system response leaked api token secret material: %s", read.Body.String())
	}

	write := perform(router, http.MethodPut, "/api/system", envelope.Data.Token, []byte(`{}`))
	if write.Code != http.StatusForbidden {
		t.Fatalf("read-only api token must not mutate system config, got %d: %s", write.Code, write.Body.String())
	}

	revoke := perform(router, http.MethodDelete, "/api/system/api-tokens/"+envelope.Data.Item.ID, adminToken, nil)
	if revoke.Code != http.StatusOK {
		t.Fatalf("expected revoke to succeed, got %d: %s", revoke.Code, revoke.Body.String())
	}
	after := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil)
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("revoked api token must be rejected, got %d: %s", after.Code, after.Body.String())
	}
}

func TestRouterUserCanSelfEnroll2FAWithoutWriteUsers(t *testing.T) {
	router, _, _, _, readerToken := newAuthzTestRouterState(t, nil)
	setup := perform(router, http.MethodPost, "/api/users/reader-id/2fa/setup", readerToken, nil)
	if setup.Code != http.StatusOK {
		t.Fatalf("user must be able to enroll own 2fa, got %d: %s", setup.Code, setup.Body.String())
	}
}

func TestRouterManagementAPITokenCannotObtainTwoFAEnrollmentSecret(t *testing.T) {
	rawToken := "cwapi_test_write_users"
	router, _, _, _, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
			ID: "write-users-token", Name: "user automation", Prefix: "cwapi_test",
			Hash: middleware.HashManagementAPIToken(rawToken), Scopes: []string{"write:users"}, Enabled: true, CreatedAt: time.Now().UTC(),
		}}
	})
	setup := perform(router, http.MethodPost, "/api/users/reader-id/2fa/setup", rawToken, nil)
	if setup.Code != http.StatusForbidden {
		t.Fatalf("api token must not obtain enrollment secret, got %d: %s", setup.Code, setup.Body.String())
	}
}

func TestRouterTwoFARecoveryAllowsAdminSessionAndRejectsAPIToken(t *testing.T) {
	rawToken := "cwapi_test_recover_users"
	router, _, store, adminToken, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
			ID: "recover-users-token", Name: "user automation", Prefix: "cwapi_test",
			Hash: middleware.HashManagementAPIToken(rawToken), Scopes: []string{"*"}, Enabled: true, CreatedAt: time.Now().UTC(),
		}}
	})
	reader, err := store.GetUserByUsername(context.Background(), "reader")
	if err != nil {
		t.Fatalf("get reader: %v", err)
	}
	reader.TwoFAEnabled = true
	reader.TwoFASecret = "JBSWY3DPEHPK3PXP"
	if err := store.UpdateUser(context.Background(), reader); err != nil {
		t.Fatalf("enable reader 2fa: %v", err)
	}

	tokenAttempt := perform(router, http.MethodPost, "/api/users/reader-id/2fa/recover", rawToken, []byte(`{"password":"admin-password","confirm_username":"reader"}`))
	if tokenAttempt.Code != http.StatusForbidden {
		t.Fatalf("api token must not recover user 2fa, got %d: %s", tokenAttempt.Code, tokenAttempt.Body.String())
	}

	recovery := perform(router, http.MethodPost, "/api/users/reader-id/2fa/recover", adminToken, []byte(`{"password":"admin-password","confirm_username":"reader"}`))
	if recovery.Code != http.StatusOK {
		t.Fatalf("admin session should recover user 2fa, got %d: %s", recovery.Code, recovery.Body.String())
	}
}

func TestRoutersCanShareAuthenticationState(t *testing.T) {
	state := handler.NewAuthState()
	first, _, _, _, readerToken := newAuthzTestRouterStateWithAuthState(t, nil, state)
	second, _, _, _, _ := newAuthzTestRouterStateWithAuthState(t, nil, state)
	setup := perform(first, http.MethodPost, "/api/users/reader-id/2fa/setup", readerToken, nil)
	if setup.Code != http.StatusOK {
		t.Fatalf("setup through first router: %d: %s", setup.Code, setup.Body.String())
	}
	var envelope struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.NewDecoder(setup.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	code, err := handlerTestTOTP(envelope.Data.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("totp: %v", err)
	}
	secondReaderToken := loginAuthzUser(t, second, "reader", "reader-password")
	enable := perform(second, http.MethodPost, "/api/users/reader-id/2fa/enable", secondReaderToken, []byte(`{"secret":"`+envelope.Data.Secret+`","code":"`+code+`"}`))
	if enable.Code != http.StatusOK {
		t.Fatalf("second router did not observe shared pending state: %d: %s", enable.Code, enable.Body.String())
	}
}

func TestRouterManagementAPITokenAllowsAdminWildcardAndRejectsCallerExcess(t *testing.T) {
	router, _, store, adminToken, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.Permissions["operator"] = []string{"manage:api_tokens", "write:system"}
	})

	wildcard := perform(router, http.MethodPost, "/api/system/api-tokens", adminToken, []byte(`{"name":"wildcard","scopes":["*"],"ttl":"1h"}`))
	if wildcard.Code != http.StatusOK {
		t.Fatalf("expected admin wildcard token creation to succeed, got %d: %s", wildcard.Code, wildcard.Body.String())
	}
	var wildcardEnvelope struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(wildcard.Body).Decode(&wildcardEnvelope); err != nil {
		t.Fatalf("decode wildcard token response: %v", err)
	}
	if wildcardEnvelope.Data.Token == "" {
		t.Fatal("admin wildcard token response did not include the one-time token")
	}
	if read := perform(router, http.MethodGet, "/api/system", wildcardEnvelope.Data.Token, nil); read.Code != http.StatusOK {
		t.Fatalf("admin wildcard token should satisfy read RBAC, got %d: %s", read.Code, read.Body.String())
	}

	createAuthzUser(t, store, "operator-id", "operator", "operator-password", "operator")
	operatorToken := loginAuthzUser(t, router, "operator", "operator-password")
	nonAdminWildcard := perform(router, http.MethodPost, "/api/system/api-tokens", operatorToken, []byte(`{"name":"wildcard","scopes":["*"],"ttl":"1h"}`))
	if nonAdminWildcard.Code != http.StatusForbidden {
		t.Fatalf("expected non-admin wildcard scope to be rejected, got %d: %s", nonAdminWildcard.Code, nonAdminWildcard.Body.String())
	}
	excess := perform(router, http.MethodPost, "/api/system/api-tokens", operatorToken, []byte(`{"name":"excess","scopes":["read:system"],"ttl":"1h"}`))
	if excess.Code != http.StatusForbidden {
		t.Fatalf("expected caller-exceeding token scope to be rejected, got %d: %s", excess.Code, excess.Body.String())
	}
}

func TestRouterConfiguredWildcardManagementAPITokenAuthorizes(t *testing.T) {
	rawToken := "cwapi_test_wildcard_secret"
	router, _, _, _, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
			ID:        "wildcard-token",
			Name:      "wildcard automation",
			Prefix:    "cwapi_test",
			Hash:      middleware.HashManagementAPIToken(rawToken),
			Scopes:    []string{"*"},
			Enabled:   true,
			CreatedAt: time.Now().UTC(),
		}}
	})

	read := perform(router, http.MethodGet, "/api/system", rawToken, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("configured wildcard api token must satisfy RBAC, got %d: %s", read.Code, read.Body.String())
	}
}

func TestRouterCaptchaLabRequiresAdministratorSession(t *testing.T) {
	rawToken := "cwapi_captcha_lab_wildcard_secret"
	router, _, _, adminToken, readerToken := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
			ID: "captcha-lab-token", Name: "captcha lab automation", Prefix: "cwapi_captcha",
			Hash: middleware.HashManagementAPIToken(rawToken), Scopes: []string{"*"}, Enabled: true, CreatedAt: time.Now().UTC(),
		}}
	})

	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{name: "missing bearer", want: http.StatusUnauthorized},
		{name: "ordinary user session", token: readerToken, want: http.StatusForbidden},
		{name: "wildcard api token", token: rawToken, want: http.StatusForbidden},
		{name: "administrator session", token: adminToken, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := perform(router, http.MethodPost, "/api/captcha/lab/challenges", tc.token, []byte(`{"type":"pow"}`))
			if got.Code != tc.want {
				t.Fatalf("challenge status = %d, want %d: %s", got.Code, tc.want, got.Body.String())
			}
		})
	}
}

func TestRouterCaptchaLabIssuesEverySupportedTypeWithoutExposingAnswers(t *testing.T) {
	router, adminToken, _ := newAuthzTestRouter(t)
	cases := []struct {
		requestType string
		wantType    captcha.BehaviorType
		wantVersion int
	}{
		{"pow", captcha.BehaviorPOW, 3}, {"curve_draw", captcha.BehaviorCurveDraw, 3},
		{"curve_slider", captcha.BehaviorCurveSlider, 3}, {"shape_slider", captcha.BehaviorShapeSlider, 2},
		{"slider_v2", captcha.BehaviorShapeSlider, 2}, {"rotate", captcha.BehaviorRotate, 3},
		{"restore_slider", captcha.BehaviorRestoreSlider, 3}, {"angle", captcha.BehaviorAngle, 3},
		{"scratch", captcha.BehaviorScratch, 3}, {"text_click", captcha.BehaviorTextClick, 3},
		{"icon_click", captcha.BehaviorIconClick, 3},
	}

	for _, tc := range cases {
		t.Run(tc.requestType, func(t *testing.T) {
			challenge := issueCaptchaLabChallenge(t, router, adminToken, tc.requestType)
			if challenge.Type != tc.wantType {
				t.Fatalf("challenge type = %q, want %q", challenge.Type, tc.wantType)
			}
			if challenge.Presentation.Version != tc.wantVersion {
				t.Fatalf("presentation version = %d, want %d", challenge.Presentation.Version, tc.wantVersion)
			}
			assertCaptchaLabTokenOpaque(t, challenge.Token)
		})
	}
}

func TestRouterCaptchaLabRejectsMissingAndUnknownType(t *testing.T) {
	router, adminToken, _ := newAuthzTestRouter(t)
	for _, body := range [][]byte{[]byte(`{}`), []byte(`{"type":"not-a-captcha"}`), []byte(`{"type":"sequence_click"}`), []byte(`{"type":"scramble_jigsaw"}`)} {
		response := perform(router, http.MethodPost, "/api/captcha/lab/challenges", adminToken, body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %s returned %d, want 400: %s", body, response.Code, response.Body.String())
		}
	}
}

func TestRouterCaptchaLabVerificationIsBoundAndOneTime(t *testing.T) {
	router, _, store, adminToken, _ := newAuthzTestRouterState(t, nil)
	createAuthzUser(t, store, "other-admin-id", "other-admin", "other-admin-password", "admin")
	otherAdminToken := loginAuthzUser(t, router, "other-admin", "other-admin-password")

	t.Run("correct proof succeeds and replay is gone", func(t *testing.T) {
		challenge := issueCaptchaLabChallenge(t, router, adminToken, "pow")
		body := captchaLabPOWResponse(t, challenge)
		verified := perform(router, http.MethodPost, "/api/captcha/lab/verify", adminToken, body)
		if verified.Code != http.StatusOK || !strings.Contains(verified.Body.String(), `"valid":true`) {
			t.Fatalf("correct proof rejected: %d: %s", verified.Code, verified.Body.String())
		}
		replay := perform(router, http.MethodPost, "/api/captcha/lab/verify", adminToken, body)
		if replay.Code != http.StatusGone {
			t.Fatalf("replay status = %d, want 410: %s", replay.Code, replay.Body.String())
		}
	})

	t.Run("wrong proof consumes token", func(t *testing.T) {
		challenge := issueCaptchaLabChallenge(t, router, adminToken, "pow")
		wrong, _ := json.Marshal(captcha.BehaviorResponse{Token: challenge.Token, Proof: "wrong"})
		invalid := perform(router, http.MethodPost, "/api/captcha/lab/verify", adminToken, wrong)
		if invalid.Code != http.StatusOK || !strings.Contains(invalid.Body.String(), `"valid":false`) {
			t.Fatalf("wrong proof status = %d, want 200 valid=false: %s", invalid.Code, invalid.Body.String())
		}
		retry := perform(router, http.MethodPost, "/api/captcha/lab/verify", adminToken, captchaLabPOWResponse(t, challenge))
		if retry.Code != http.StatusGone {
			t.Fatalf("retry after wrong proof status = %d, want 410: %s", retry.Code, retry.Body.String())
		}
	})

	t.Run("challenge is bound to issuing user", func(t *testing.T) {
		challenge := issueCaptchaLabChallenge(t, router, adminToken, "pow")
		body := captchaLabPOWResponse(t, challenge)
		crossUser := perform(router, http.MethodPost, "/api/captcha/lab/verify", otherAdminToken, body)
		if crossUser.Code != http.StatusOK || !strings.Contains(crossUser.Body.String(), `"valid":false`) {
			t.Fatalf("cross-user verification status = %d, want 200 valid=false: %s", crossUser.Code, crossUser.Body.String())
		}
		retry := perform(router, http.MethodPost, "/api/captcha/lab/verify", adminToken, body)
		if retry.Code != http.StatusGone {
			t.Fatalf("cross-user attempt must consume token, got %d: %s", retry.Code, retry.Body.String())
		}
	})
}

func TestRouterCaptchaLabConcurrentVerificationSucceedsOnce(t *testing.T) {
	router, adminToken, _ := newAuthzTestRouter(t)
	challenge := issueCaptchaLabChallenge(t, router, adminToken, "pow")
	body := captchaLabPOWResponse(t, challenge)

	const attempts = 12
	start := make(chan struct{})
	statuses := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses <- perform(router, http.MethodPost, "/api/captcha/lab/verify", adminToken, body).Code
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)

	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusGone] != attempts-1 {
		t.Fatalf("concurrent statuses = %#v, want one 200 and %d 410s", counts, attempts-1)
	}
}

func TestRouterManagementAPITokenCreateRequiresFeatureEnabled(t *testing.T) {
	router, _, _, adminToken, _ := newAuthzTestRouterState(t, nil)

	created := perform(router, http.MethodPost, "/api/system/api-tokens", adminToken, []byte(`{"name":"disabled automation","scopes":["read:system"],"ttl":"1h"}`))
	if created.Code != http.StatusBadRequest {
		t.Fatalf("disabled management api must reject token creation, got %d: %s", created.Code, created.Body.String())
	}
	if !bytes.Contains(created.Body.Bytes(), []byte("API_TOKEN_DISABLED")) {
		t.Fatalf("expected API_TOKEN_DISABLED, body=%s", created.Body.String())
	}
}

func TestRouterManagementAPITokenRejectsExpiredConfiguredToken(t *testing.T) {
	rawToken := "cwapi_test_expired_secret"
	router, _, _, _, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []config.ManagementAPITokenConfig{{
			ID:        "expired-token",
			Name:      "expired automation",
			Prefix:    "cwapi_test",
			Hash:      middleware.HashManagementAPIToken(rawToken),
			Scopes:    []string{"read:system"},
			Enabled:   true,
			ExpiresAt: time.Now().UTC().Add(-time.Minute),
		}}
	})

	read := perform(router, http.MethodGet, "/api/system", rawToken, nil)
	if read.Code != http.StatusUnauthorized {
		t.Fatalf("expired api token must be rejected, got %d: %s", read.Code, read.Body.String())
	}
}

func TestRouterManagementAPITokenAuditIncludesStableSubject(t *testing.T) {
	router, _, _, adminToken, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.Audit.Enabled = true
	})

	created := perform(router, http.MethodPost, "/api/system/api-tokens", adminToken, []byte(`{"name":"audit automation","scopes":["read:system"],"ttl":"1h"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("expected api token creation to succeed, got %d: %s", created.Code, created.Body.String())
	}
	var createdEnvelope struct {
		Data struct {
			Token string `json:"token"`
			Item  struct {
				ID string `json:"id"`
			} `json:"item"`
		} `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&createdEnvelope); err != nil {
		t.Fatalf("decode create token response: %v", err)
	}
	if createdEnvelope.Data.Token == "" || createdEnvelope.Data.Item.ID == "" {
		t.Fatalf("expected token and id in create response: %+v", createdEnvelope.Data)
	}

	read := perform(router, http.MethodGet, "/api/system", createdEnvelope.Data.Token, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("api token should read system config, got %d: %s", read.Code, read.Body.String())
	}

	audit := perform(router, http.MethodGet, "/api/audit", adminToken, nil)
	if audit.Code != http.StatusOK {
		t.Fatalf("admin should read audit entries, got %d: %s", audit.Code, audit.Body.String())
	}
	var auditEnvelope struct {
		Data []struct {
			Subject string `json:"subject"`
			User    string `json:"user"`
			Role    string `json:"role"`
			Path    string `json:"path"`
		} `json:"data"`
	}
	if err := json.NewDecoder(audit.Body).Decode(&auditEnvelope); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}
	wantSubject := "api-token:" + createdEnvelope.Data.Item.ID
	for _, entry := range auditEnvelope.Data {
		if entry.Path == "/api/system" && entry.Subject == wantSubject && entry.Role == "api_token" {
			return
		}
	}
	t.Fatalf("expected audit entry for %s on /api/system, got %+v", wantSubject, auditEnvelope.Data)
}

func TestRouterManagementAPITokenLastUsedPersistsAcrossRestartAndIsThrottled(t *testing.T) {
	router, cfg, store, adminToken, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
	})
	created := perform(router, http.MethodPost, "/api/system/api-tokens", adminToken, []byte(`{"name":"restart","scopes":["read:system"],"ttl":"1h"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create token: %d %s", created.Code, created.Body.String())
	}
	var envelope struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if got := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil); got.Code != http.StatusOK {
		t.Fatalf("first token use: %d %s", got.Code, got.Body.String())
	}
	configPath := filepath.Join(filepath.Dir(cfg.Storage.SQLite.Path), "cheesewaf.yaml")
	firstInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat persisted config: %v", err)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("reload persisted config: %v", err)
	}
	if len(loaded.APISec.ManagementAPI.Tokens) != 1 || loaded.APISec.ManagementAPI.Tokens[0].LastUsedAt.IsZero() {
		t.Fatalf("last-used timestamp was not persisted: %+v", loaded.APISec.ManagementAPI.Tokens)
	}
	time.Sleep(20 * time.Millisecond)
	if got := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil); got.Code != http.StatusOK {
		t.Fatalf("throttled token use: %d %s", got.Code, got.Body.String())
	}
	secondInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat throttled config: %v", err)
	}
	if !secondInfo.ModTime().Equal(firstInfo.ModTime()) {
		t.Fatalf("token use inside throttle window rewrote config: first=%s second=%s", firstInfo.ModTime(), secondInfo.ModTime())
	}
	restarted := NewRouter(Options{Config: loaded, ConfigPath: configPath, Store: store, Secret: "router-authz-test-secret", AssistantApprovals: ai.NewApprovalStore()})
	if got := perform(restarted, http.MethodGet, "/api/system", envelope.Data.Token, nil); got.Code != http.StatusOK {
		t.Fatalf("persisted token after restart: %d %s", got.Code, got.Body.String())
	}
}

func TestRouterManagementAPITokenConcurrentUseAndRevoke(t *testing.T) {
	router, _, _, adminToken, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.ManagementAPI.Enabled = true
	})
	created := perform(router, http.MethodPost, "/api/system/api-tokens", adminToken, []byte(`{"name":"concurrent","scopes":["read:system"],"ttl":"1h"}`))
	if created.Code != http.StatusOK {
		t.Fatalf("create token: %d %s", created.Code, created.Body.String())
	}
	var envelope struct {
		Data struct {
			Token string `json:"token"`
			Item  struct {
				ID string `json:"id"`
			} `json:"item"`
		} `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil)
			if got.Code != http.StatusOK && got.Code != http.StatusUnauthorized {
				t.Errorf("concurrent auth returned %d: %s", got.Code, got.Body.String())
			}
		}()
	}
	revoked := perform(router, http.MethodDelete, "/api/system/api-tokens/"+envelope.Data.Item.ID, adminToken, nil)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke token: %d %s", revoked.Code, revoked.Body.String())
	}
	wg.Wait()
	if got := perform(router, http.MethodGet, "/api/system", envelope.Data.Token, nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token remained usable: %d %s", got.Code, got.Body.String())
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

func TestRouterLoginCAPTCHAUsesStableEphemeralSecretWhenRuntimeSecretMissing(t *testing.T) {
	tempDir := t.TempDir()
	cfg := config.Default()
	cfg.Console.Login.CAPTCHA.Mode = "pow"
	cfg.Protection.Bot.Secret = config.BotSecretPlaceholder
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
	router := NewRouter(Options{Config: &cfg, ConfigPath: configPath, Store: store})

	client := newLoginCAPTCHATestClient(router)
	payload := solveLoginCAPTCHA(t, client)
	if payload == nil {
		t.Fatal("expected a login captcha payload")
	}
	body, _ := json.Marshal(payload)
	recorder := client.perform(http.MethodPost, "/api/auth/captcha/verify", body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected captcha signed with ephemeral secret to verify, got %d: %s", recorder.Code, recorder.Body.String())
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

	client := newLoginCAPTCHATestClient(router)
	pow := solveLoginCAPTCHA(t, client)
	body, _ := json.Marshal(map[string]any{"username": "admin", "password": "admin-password", "captcha": pow})
	recorder := client.perform(http.MethodPost, "/api/auth/login", body)
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

func TestRouterLoginCAPTCHARejectsTrailingJSONDocument(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)

	recorder := perform(router, http.MethodPost, "/api/auth/captcha", "", []byte(`{} {}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected trailing JSON captcha request to be rejected, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("exactly one JSON document")) {
		t.Fatalf("expected explicit trailing JSON error, body=%s", recorder.Body.String())
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

	client := newLoginCAPTCHATestClient(router)
	challenge := requestSliderLoginCAPTCHA(t, client, []byte(`{}`))
	validX := findValidSliderX(t, cfg, secret, client, challenge)
	validTrack := sliderTrackForTest(validX, challenge.MinDragMS+50)
	invalid, _ := json.Marshal(map[string]any{
		"username": "admin",
		"mode":     "slider",
		"slider": map[string]any{
			"token":   challenge.Token,
			"x":       0,
			"drag_ms": challenge.MinDragMS + 50,
			"track":   sliderTrackForTest(0, challenge.MinDragMS+50),
		},
	})
	recorder := client.perform(http.MethodPost, "/api/auth/captcha/verify", invalid)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected bad slider x to fail, got %d: %s", recorder.Code, recorder.Body.String())
	}
	challenge = requestSliderLoginCAPTCHA(t, client, []byte(`{}`))
	validX = findValidSliderX(t, cfg, secret, client, challenge)
	validTrack = sliderTrackForTest(validX, challenge.MinDragMS+50)

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
	recorder = client.perform(http.MethodPost, "/api/auth/login", rawLogin)
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
	recorder = client.perform(http.MethodPost, "/api/auth/login", rawLoginWithTrack)
	if recorder.Code != http.StatusUnauthorized || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected raw slider proof login to require receipt, got %d: %s", recorder.Code, recorder.Body.String())
	}

	valid, _ := json.Marshal(map[string]any{
		"username": "admin",
		"mode":     "slider",
		"slider": map[string]any{
			"token":   challenge.Token,
			"x":       validX,
			"drag_ms": challenge.MinDragMS + 50,
			"track":   validTrack,
		},
	})
	recorder = client.perform(http.MethodPost, "/api/auth/captcha/verify", valid)
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

	reverify := client.perform(http.MethodPost, "/api/auth/captcha/verify", valid)
	if reverify.Code != http.StatusUnauthorized {
		t.Fatalf("slider token should be consumed after issuing receipt, got %d: %s", reverify.Code, reverify.Body.String())
	}

	loginBody, _ := json.Marshal(map[string]any{
		"username": "admin",
		"password": "admin-password",
		"captcha":  map[string]any{"mode": "slider", "receipt": verified.Data.Receipt},
	})
	recorder = client.perform(http.MethodPost, "/api/auth/login", loginBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected receipt-backed login to succeed, got %d: %s", recorder.Code, recorder.Body.String())
	}

	reuse := client.perform(http.MethodPost, "/api/auth/login", loginBody)
	if reuse.Code != http.StatusUnauthorized || !bytes.Contains(reuse.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("receipt should be one-time, got %d: %s", reuse.Code, reuse.Body.String())
	}
}

func TestRouterLoginCAPTCHAVerifyRejectsBlankUsername(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)
	client := newLoginCAPTCHATestClient(router)
	payload := solveLoginCAPTCHA(t, client)
	payload["username"] = "  "
	body, _ := json.Marshal(payload)
	recorder := client.perform(http.MethodPost, "/api/auth/captcha/verify", body)
	if recorder.Code != http.StatusBadRequest || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected blank username to be rejected without account disclosure, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterLoginCAPTCHAReceiptRejectsDifferentUsername(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)
	client := newLoginCAPTCHATestClient(router)
	payload := solveLoginCAPTCHA(t, client)
	payload["username"] = "admin"
	body, _ := json.Marshal(payload)
	verifiedRecorder := client.perform(http.MethodPost, "/api/auth/captcha/verify", body)
	if verifiedRecorder.Code != http.StatusOK {
		t.Fatalf("expected captcha proof to issue receipt, got %d: %s", verifiedRecorder.Code, verifiedRecorder.Body.String())
	}
	var verified struct {
		Data struct {
			Receipt string `json:"receipt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(verifiedRecorder.Body).Decode(&verified); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	loginBody, _ := json.Marshal(map[string]any{
		"username": "different-user",
		"password": "admin-password",
		"captcha":  map[string]any{"mode": "pow", "receipt": verified.Data.Receipt},
	})
	recorder := client.perform(http.MethodPost, "/api/auth/login", loginBody)
	if recorder.Code != http.StatusUnauthorized || !bytes.Contains(recorder.Body.Bytes(), []byte("INVALID_CAPTCHA")) {
		t.Fatalf("expected cross-username receipt to receive generic captcha rejection, got %d: %s", recorder.Code, recorder.Body.String())
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

	client := newLoginCAPTCHATestClient(router)
	challenge := requestSliderLoginCAPTCHA(t, client, []byte(`{}`))
	validX := findValidSliderX(t, cfg, secret, client, challenge)
	validTrack := sliderTrackForTest(validX, challenge.MinDragMS+50)
	badX := 0
	if validX == 0 {
		badX = challenge.TrackWidth
	}
	badTrack := sliderTrackForTest(badX, challenge.MinDragMS+50)
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(map[string]any{
			"username": "admin",
			"mode":     "slider",
			"slider": map[string]any{
				"token":   challenge.Token,
				"x":       badX,
				"drag_ms": challenge.MinDragMS + 50,
				"track":   badTrack,
			},
		})
		recorder := client.perform(http.MethodPost, "/api/auth/captcha/verify", body)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected bad slider attempt %d to fail, got %d: %s", i+1, recorder.Code, recorder.Body.String())
		}
	}
	valid, _ := json.Marshal(map[string]any{
		"username": "admin",
		"mode":     "slider",
		"slider": map[string]any{
			"token":   challenge.Token,
			"x":       validX,
			"drag_ms": challenge.MinDragMS + 50,
			"track":   validTrack,
		},
	})
	recorder := client.perform(http.MethodPost, "/api/auth/captcha/verify", valid)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("locked slider token should not issue receipt after failures, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterLoginCAPTCHAAllowsClientRequestedPowWhenConfiguredForSlider(t *testing.T) {
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

	recorder := perform(router, http.MethodPost, "/api/auth/captcha", "", []byte(`{"mode":"pow"}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected captcha challenge, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data struct {
			Mode      string `json:"mode"`
			Challenge *struct {
				Challenge string `json:"challenge"`
			} `json:"challenge"`
			Slider *struct {
				Token string `json:"token"`
			} `json:"slider"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode captcha challenge: %v", err)
	}
	if envelope.Data.Mode != "pow" || envelope.Data.Challenge == nil || envelope.Data.Challenge.Challenge == "" || envelope.Data.Slider != nil {
		t.Fatalf("client-requested pow should receive a PoW challenge without a slider, got %+v", envelope.Data)
	}
}

func TestRouterLoginCAPTCHAPowProofIsOneTime(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)

	client := newLoginCAPTCHATestClient(router)
	payload := solveLoginCAPTCHA(t, client)
	if payload == nil {
		t.Fatal("expected pow captcha payload")
	}
	body, _ := json.Marshal(payload)
	first := client.perform(http.MethodPost, "/api/auth/captcha/verify", body)
	if first.Code != http.StatusOK {
		t.Fatalf("expected first pow proof to verify, got %d: %s", first.Code, first.Body.String())
	}
	second := client.perform(http.MethodPost, "/api/auth/captcha/verify", body)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("expected replayed pow proof to be rejected, got %d: %s", second.Code, second.Body.String())
	}
}

func TestRouterLoginRateLimitsByIPWithoutLockingUsernameAcrossIPs(t *testing.T) {
	router, _, _ := newAuthzTestRouterWithConfig(t, func(cfg *config.Config) {
		cfg.Console.Login.CAPTCHA.Enabled = false
	})
	for i := 0; i < loginRateLimitMaxFailuresForTest(); i++ {
		body, _ := json.Marshal(map[string]string{"username": fmt.Sprintf("missing-%d", i), "password": "wrong"})
		recorder := performFromIP(router, http.MethodPost, "/api/auth/login", "", body, "198.51.100.10:1234")
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected failed login %d by IP, got %d: %s", i+1, recorder.Code, recorder.Body.String())
		}
	}
	validBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "admin-password"})
	blockedByIP := performFromIP(router, http.MethodPost, "/api/auth/login", "", validBody, "198.51.100.10:1234")
	if blockedByIP.Code != http.StatusTooManyRequests {
		t.Fatalf("expected IP rate limit, got %d: %s", blockedByIP.Code, blockedByIP.Body.String())
	}

	router, _, _ = newAuthzTestRouterWithConfig(t, func(cfg *config.Config) {
		cfg.Console.Login.CAPTCHA.Enabled = false
	})
	for i := 0; i < loginRateLimitMaxFailuresForTest(); i++ {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
		recorder := performFromIP(router, http.MethodPost, "/api/auth/login", "", body, fmt.Sprintf("198.51.100.%d:1234", i+20))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected failed login %d by username, got %d: %s", i+1, recorder.Code, recorder.Body.String())
		}
	}
	loginFromFreshIP := performFromIP(router, http.MethodPost, "/api/auth/login", "", validBody, "198.51.100.99:1234")
	if loginFromFreshIP.Code != http.StatusOK {
		t.Fatalf("distributed failures must not hard-lock a legitimate account from a fresh IP, got %d: %s", loginFromFreshIP.Code, loginFromFreshIP.Body.String())
	}
}

func TestRouterLoginRateLimitCannotBeBypassedBySpoofedForwardedHeader(t *testing.T) {
	router, _, _ := newAuthzTestRouterWithConfig(t, func(cfg *config.Config) {
		cfg.Console.Login.CAPTCHA.Enabled = false
	})
	for i := 0; i < loginRateLimitMaxFailuresForTest(); i++ {
		request := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"username":"admin","password":"wrong"}`)))
		request.RemoteAddr = "203.0.113.40:41000"
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"username":"admin","password":"wrong"}`)))
	request.RemoteAddr = "203.0.113.40:41001"
	request.Header.Set("X-Forwarded-For", "198.51.100.200")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed forwarding header bypassed socket-peer limit: %d %s", recorder.Code, recorder.Body.String())
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

func TestRouterAIApprovalRequiresScopedSecondPersonForModifyTool(t *testing.T) {
	router, _, store, _, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.Permissions["ai_writer"] = []string{"write:ai"}
		cfg.APISec.Permissions["ai_approver"] = []string{"approve:ai"}
	})
	createAuthzUser(t, store, "ai-writer-id", "ai-writer", "writer-password", "ai_writer")
	createAuthzUser(t, store, "ai-approver-id", "ai-approver", "approver-password", "ai_approver")
	writerToken := loginAuthzUser(t, router, "ai-writer", "writer-password")
	approverToken := loginAuthzUser(t, router, "ai-approver", "approver-password")

	args := `{"area":"bot_cc","level":"high"}`
	created := perform(router, http.MethodPost, "/api/ai/tools/execute", writerToken, []byte(`{"name":"set_protection_level","args":`+args+`}`))
	if created.Code != http.StatusOK {
		t.Fatalf("expected approval request creation, got %d: %s", created.Code, created.Body.String())
	}
	var envelope struct {
		Data struct {
			Approval *struct {
				ID string `json:"id"`
			} `json:"approval"`
		} `json:"data"`
	}
	if err := json.NewDecoder(created.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if envelope.Data.Approval == nil || envelope.Data.Approval.ID == "" {
		t.Fatalf("expected approval id, got %+v", envelope.Data.Approval)
	}

	selfApprove := perform(router, http.MethodPost, "/api/ai/tools/approvals/"+envelope.Data.Approval.ID+"/approve", writerToken, nil)
	if selfApprove.Code != http.StatusForbidden {
		t.Fatalf("modify request must reject self-approval, got %d: %s", selfApprove.Code, selfApprove.Body.String())
	}
	approve := perform(router, http.MethodPost, "/api/ai/tools/approvals/"+envelope.Data.Approval.ID+"/approve", approverToken, nil)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve:ai token should approve, got %d: %s", approve.Code, approve.Body.String())
	}
}

func TestRouterAIApprovalRecoveryPreservesObjectScope(t *testing.T) {
	router, _, store, _, _ := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.APISec.Permissions["ai_writer"] = []string{"write:ai"}
		cfg.APISec.Permissions["ai_approver"] = []string{"approve:ai"}
	})
	createAuthzUser(t, store, "ai-writer-id", "ai-writer", "writer-password", "ai_writer")
	createAuthzUser(t, store, "ai-approver-id", "ai-approver", "approver-password", "ai_approver")
	writerToken := loginAuthzUser(t, router, "ai-writer", "writer-password")
	approverToken := loginAuthzUser(t, router, "ai-approver", "approver-password")

	created := perform(router, http.MethodPost, "/api/ai/tools/execute", writerToken, []byte(`{"name":"set_protection_level","args":{"area":"bot_cc","level":"high"}}`))
	var envelope struct {
		Data struct {
			Approval struct {
				ID string `json:"id"`
			} `json:"approval"`
		} `json:"data"`
	}
	if created.Code != http.StatusOK || json.NewDecoder(created.Body).Decode(&envelope) != nil || envelope.Data.Approval.ID == "" {
		t.Fatalf("create approval failed: code=%d body=%s", created.Code, created.Body.String())
	}

	if own := perform(router, http.MethodGet, "/api/ai/tools/approvals/"+envelope.Data.Approval.ID, writerToken, nil); own.Code != http.StatusOK {
		t.Fatalf("expected requester recovery access, got %d: %s", own.Code, own.Body.String())
	}
	if cross := perform(router, http.MethodGet, "/api/ai/tools/approvals/"+envelope.Data.Approval.ID, approverToken, nil); cross.Code != http.StatusOK {
		t.Fatalf("expected approve:ai cross-user recovery access, got %d: %s", cross.Code, cross.Body.String())
	}
}

func TestRouterNotificationsContractAndIsolation(t *testing.T) {
	router, _, store, adminToken, readerToken := newAuthzTestRouterState(t, nil)
	ctx := context.Background()
	for _, item := range []*storage.Notification{
		{ID: "admin-unread", UserID: "admin-id", Title: "Admin unread"},
		{ID: "admin-read", UserID: "admin-id", Title: "Admin read", Read: true},
		{ID: "reader-only", UserID: "reader-id", Title: "Reader only"},
	} {
		if err := store.CreateNotification(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	list := perform(router, http.MethodGet, "/api/notifications?page=1&limit=10&filter=unread", adminToken, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list notifications: %d %s", list.Code, list.Body.String())
	}
	var envelope struct {
		Data struct {
			Items         []storage.Notification `json:"items"`
			Total         int64                  `json:"total"`
			FilteredTotal int64                  `json:"filtered_total"`
			Unread        int64                  `json:"unread"`
			Page          int                    `json:"page"`
			Limit         int                    `json:"limit"`
		} `json:"data"`
	}
	if err := json.NewDecoder(list.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Total != 2 || envelope.Data.FilteredTotal != 1 || envelope.Data.Unread != 1 || envelope.Data.Page != 1 || envelope.Data.Limit != 10 || len(envelope.Data.Items) != 1 {
		t.Fatalf("unexpected notification contract: %+v", envelope.Data)
	}
	crossUser := perform(router, http.MethodPatch, "/api/notifications/reader-only", adminToken, []byte(`{"read":true}`))
	if crossUser.Code != http.StatusNotFound {
		t.Fatalf("cross-user notification update must be hidden, got %d: %s", crossUser.Code, crossUser.Body.String())
	}
	update := perform(router, http.MethodPatch, "/api/notifications/admin-unread", adminToken, []byte(`{"read":true,"pinned":true}`))
	if update.Code != http.StatusOK {
		t.Fatalf("update notification: %d %s", update.Code, update.Body.String())
	}
	var updatedEnvelope struct {
		Data storage.Notification `json:"data"`
	}
	if err := json.NewDecoder(update.Body).Decode(&updatedEnvelope); err != nil {
		t.Fatal(err)
	}
	if !updatedEnvelope.Data.Read || !updatedEnvelope.Data.Pinned || updatedEnvelope.Data.Type != "info" {
		t.Fatalf("unexpected updated notification: %+v", updatedEnvelope.Data)
	}
	markAll := perform(router, http.MethodPost, "/api/notifications/read-all", readerToken, nil)
	if markAll.Code != http.StatusOK {
		t.Fatalf("reader mark all: %d %s", markAll.Code, markAll.Body.String())
	}
	adminList := perform(router, http.MethodGet, "/api/notifications?filter=unread", adminToken, nil)
	if err := json.NewDecoder(adminList.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Total != 2 || envelope.Data.Unread != 0 {
		t.Fatalf("reader action changed admin unread count: %+v", envelope.Data)
	}
	clear := perform(router, http.MethodDelete, "/api/notifications", readerToken, nil)
	if clear.Code != http.StatusOK {
		t.Fatalf("reader clear: %d %s", clear.Code, clear.Body.String())
	}
	adminAfterClear := perform(router, http.MethodGet, "/api/notifications", adminToken, nil)
	if err := json.NewDecoder(adminAfterClear.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Total != 2 {
		t.Fatalf("reader clear changed admin notifications: %+v", envelope.Data)
	}
	for _, path := range []string{"/api/notifications?filter=invalid", "/api/notifications?limit=101"} {
		bad := perform(router, http.MethodGet, path, adminToken, nil)
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d: %s", path, bad.Code, bad.Body.String())
		}
	}
}

func newAuthzTestRouter(t *testing.T) (http.Handler, string, string) {
	router, _, _, adminToken, readerToken := newAuthzTestRouterState(t, func(cfg *config.Config) {
		cfg.Monitor.Prometheus.Enabled = true
		cfg.Monitor.Prometheus.Public = false
	})
	return router, adminToken, readerToken
}

func newAuthzTestRouterWithConfig(t *testing.T, mutate func(*config.Config)) (http.Handler, string, string) {
	router, _, _, adminToken, readerToken := newAuthzTestRouterState(t, mutate)
	return router, adminToken, readerToken
}

func newAuthzTestRouterState(t *testing.T, mutate func(*config.Config)) (http.Handler, *config.Config, storage.Store, string, string) {
	return newAuthzTestRouterStateWithAuthState(t, mutate, nil)
}

func newAuthzTestRouterStateWithAuthState(t *testing.T, mutate func(*config.Config), authState *handler.AuthState) (http.Handler, *config.Config, storage.Store, string, string) {
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
		Config:             &cfg,
		ConfigPath:         configPath,
		Store:              store,
		Secret:             "router-authz-test-secret",
		AuthState:          authState,
		AssistantApprovals: ai.NewApprovalStore(),
	})
	adminToken := loginAuthzUser(t, router, "admin", "admin-password")
	readerToken := loginAuthzUser(t, router, "reader", "reader-password")
	return router, &cfg, store, adminToken, readerToken
}

func handlerTestTOTP(secret string, now time.Time) (string, error) {
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(secret)
	if err != nil {
		return "", err
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (int(sum[offset])&0x7f)<<24 | int(sum[offset+1])<<16 | int(sum[offset+2])<<8 | int(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000), nil
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
	client := newLoginCAPTCHATestClient(router)
	bodyPayload := map[string]any{"username": username, "password": password}
	if payload := solveLoginCAPTCHA(t, client); payload != nil {
		payload["username"] = username
		verifyBody, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal captcha verification: %v", err)
		}
		verified := client.perform(http.MethodPost, "/api/auth/captcha/verify", verifyBody)
		if verified.Code != http.StatusOK {
			t.Fatalf("verify login captcha for %s returned %d: %s", username, verified.Code, verified.Body.String())
		}
		var envelope struct {
			Data struct {
				Receipt string `json:"receipt"`
			} `json:"data"`
		}
		if err := json.NewDecoder(verified.Body).Decode(&envelope); err != nil {
			t.Fatalf("decode captcha verification: %v", err)
		}
		if envelope.Data.Receipt == "" {
			t.Fatal("captcha verification did not include a receipt")
		}
		bodyPayload["captcha"] = map[string]any{
			"username": username,
			"mode":     payload["mode"],
			"receipt":  envelope.Data.Receipt,
		}
	}
	body, err := json.Marshal(bodyPayload)
	if err != nil {
		t.Fatalf("marshal login: %v", err)
	}
	recorder := client.perform(http.MethodPost, "/api/auth/login", body)
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

type loginCAPTCHATestClient struct {
	router  http.Handler
	cookies map[string]*http.Cookie
}

func newLoginCAPTCHATestClient(router http.Handler) *loginCAPTCHATestClient {
	return &loginCAPTCHATestClient{router: router, cookies: make(map[string]*http.Cookie)}
}

func (client *loginCAPTCHATestClient) perform(method, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range client.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	client.router.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(client.cookies, cookie.Name)
			continue
		}
		client.cookies[cookie.Name] = cookie
	}
	return recorder
}

func (client *loginCAPTCHATestClient) sliderClientKey(t *testing.T) string {
	t.Helper()
	cookie, ok := client.cookies["cw_captcha_client"]
	if !ok {
		t.Fatal("captcha challenge did not set the anonymous client cookie")
	}
	rawID, _, ok := strings.Cut(cookie.Value, ".")
	if !ok || rawID == "" {
		t.Fatal("captcha challenge set an invalid anonymous client cookie")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(strings.TrimSpace(rawID)))
	_, _ = hash.Write([]byte{0})
	owner := "client:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	return "192.0.2.1\n\n" + owner
}

func solveLoginCAPTCHA(t *testing.T, client *loginCAPTCHATestClient) map[string]any {
	return solveLoginCAPTCHAWithRequest(t, client, []byte(`{}`))
}

func solveLoginCAPTCHAWithRequest(t *testing.T, client *loginCAPTCHATestClient, requestBody []byte) map[string]any {
	t.Helper()
	recorder := client.perform(http.MethodPost, "/api/auth/captcha", requestBody)
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
				"username":  "admin",
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

func requestSliderLoginCAPTCHA(t *testing.T, client *loginCAPTCHATestClient, requestBody []byte) sliderLoginCAPTCHAForTest {
	t.Helper()
	recorder := client.perform(http.MethodPost, "/api/auth/captcha", requestBody)
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

func findValidSliderX(t *testing.T, cfg config.Config, secret string, client *loginCAPTCHATestClient, challenge sliderLoginCAPTCHAForTest) int {
	t.Helper()
	for x := 0; x <= challenge.TrackWidth; x++ {
		if captcha.VerifySlider(captcha.SliderOptions{
			Secret:    secret,
			Purpose:   "admin-login-slider",
			ClientKey: client.sliderClientKey(t),
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
			Track:  sliderTrackForTest(x, challenge.MinDragMS+50),
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

func issueCaptchaLabChallenge(t *testing.T, router http.Handler, token, kind string) captcha.BehaviorChallenge {
	t.Helper()
	body, err := json.Marshal(map[string]string{"type": kind})
	if err != nil {
		t.Fatalf("marshal captcha lab request: %v", err)
	}
	response := perform(router, http.MethodPost, "/api/captcha/lab/challenges", token, body)
	if response.Code != http.StatusOK {
		t.Fatalf("issue captcha lab %q returned %d: %s", kind, response.Code, response.Body.String())
	}
	var envelope struct {
		Data captcha.BehaviorChallenge `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode captcha lab challenge: %v", err)
	}
	if envelope.Data.Token == "" || envelope.Data.ExpiresAt == "" {
		t.Fatalf("incomplete captcha lab challenge: %+v", envelope.Data)
	}
	return envelope.Data
}

func captchaLabPOWResponse(t *testing.T, challenge captcha.BehaviorChallenge) []byte {
	t.Helper()
	proof, ok := captcha.SolveBehaviorPOW(challenge.Presentation.POWSalt, challenge.Presentation.POWDifficulty, 1<<22)
	if !ok {
		t.Fatalf("failed to solve captcha lab POW with difficulty %d", challenge.Presentation.POWDifficulty)
	}
	body, err := json.Marshal(captcha.BehaviorResponse{Token: challenge.Token, Proof: proof})
	if err != nil {
		t.Fatalf("marshal captcha lab proof: %v", err)
	}
	return body
}

func assertCaptchaLabTokenOpaque(t *testing.T, token string) {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("captcha lab token is not opaque base64url: %v", err)
	}
	for _, field := range []string{`"point"`, `"points"`, `"angle"`, `"curve"`, `"region"`, `"permutation"`, `"coverage"`} {
		if bytes.Contains(decoded, []byte(field)) {
			t.Fatalf("captcha lab token exposes answer field %s", field)
		}
	}
}

func perform(router http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	return performFromIP(router, method, path, token, body, "")
}

func performFromIP(router http.Handler, method, path, token string, body []byte, remoteAddr string) *httptest.ResponseRecorder {
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
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func loginRateLimitMaxFailuresForTest() int {
	return 5
}
