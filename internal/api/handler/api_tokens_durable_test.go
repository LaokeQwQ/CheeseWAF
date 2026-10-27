package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
	tokensservice "github.com/LaokeQwQ/CheeseWAF/internal/tokens/service"
)

type durableTokenClock struct{ now time.Time }

func (c durableTokenClock) Now() time.Time { return c.now }

type durableTokenEpoch uint64

func (e durableTokenEpoch) CurrentEpoch(context.Context, string) (uint64, error) {
	return uint64(e), nil
}

func newDurableTokenHandler(t *testing.T) (*Handler, *tokensservice.Service) {
	t.Helper()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	service, err := tokensservice.New(tokensservice.Config{
		Persistence: tokens.NewMemoryPersistence(),
		Clock:       durableTokenClock{now: now},
		Epochs:      durableTokenEpoch(3),
		LeaseID:     "lease-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{TokenService: service, PolicyEpoch: 3, now: func() time.Time { return now }}, service
}

func TestDurableManagementTokenLifecycle(t *testing.T) {
	h, _ := newDurableTokenHandler(t)
	createReq := httptest.NewRequest(http.MethodPost, "/api/tokens", nil)
	recorder := httptest.NewRecorder()
	h.createDurableManagementAPIToken(recorder, createReq, "deploy-bot", "ci notes", []string{"write:sites", "read:logs"}, tokens.Lifetime{ExpiresAt: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Token string                 `json:"token"`
			Item  managementAPITokenView `json:"item"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	raw := payload.Data.Token
	if !strings.HasPrefix(raw, "cwapi_") || !strings.Contains(raw, "~") {
		t.Fatalf("raw token shape=%q", raw)
	}
	if payload.Data.Item.Name != "deploy-bot" || payload.Data.Item.Notes != "ci notes" || len(payload.Data.Item.Scopes) != 2 {
		t.Fatalf("item=%+v", payload.Data.Item)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/api/sites", nil)
	claims, ok := h.authenticateDurableManagementToken(authReq, raw)
	if !ok || claims == nil {
		t.Fatal("durable token did not authenticate")
	}
	if claims.Subject != "system" || claims.Role != "api-token" || len(claims.Scopes) != 2 || claims.Scopes[0] != "write:sites" {
		t.Fatalf("claims=%+v", claims)
	}
	if claims.Expires == 0 {
		t.Fatal("claims must carry the token expiry")
	}
	if _, ok := h.authenticateDurableManagementToken(authReq, "cwapi_missing_secret"); ok {
		t.Fatal("malformed token must not authenticate")
	}

	revoke := httptest.NewRecorder()
	h.revokeDurableManagementAPIToken(revoke, httptest.NewRequest(http.MethodDelete, "/api/tokens/"+payload.Data.Item.ID, nil), payload.Data.Item.ID)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if _, ok := h.authenticateDurableManagementToken(authReq, raw); ok {
		t.Fatal("revoked token must not authenticate")
	}
}

func TestDurableManagementTokenList(t *testing.T) {
	h, _ := newDurableTokenHandler(t)
	recorder := httptest.NewRecorder()
	h.createDurableManagementAPIToken(recorder, httptest.NewRequest(http.MethodPost, "/api/tokens", nil), "listed", "", []string{"read:logs"}, tokens.Lifetime{ExpiresAt: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if recorder.Code != http.StatusOK {
		t.Fatalf("create status=%d", recorder.Code)
	}
	items, err := h.listDurableManagementTokens(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "listed" || !items[0].Enabled {
		t.Fatalf("items=%+v", items)
	}
}

func TestDurableManagementTokenRejectsScopelessRequest(t *testing.T) {
	h, _ := newDurableTokenHandler(t)
	recorder := httptest.NewRecorder()
	h.createDurableManagementAPIToken(recorder, httptest.NewRequest(http.MethodPost, "/api/tokens", nil), "bad", "", []string{"write"}, tokens.Lifetime{ExpiresAt: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}, time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
