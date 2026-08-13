package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"golang.org/x/crypto/bcrypt"
)

type middlewareFakeClock struct {
	now time.Time
}

func (c *middlewareFakeClock) Now() time.Time {
	return c.now
}

type recordingSessionValidator struct {
	active bool
	times  []time.Time
}

func (v *recordingSessionValidator) IsSessionActive(_ context.Context, _, _ string, now time.Time) (bool, error) {
	v.times = append(v.times, now)
	return v.active, nil
}

func TestTokenManagerFailsClosedWhenEphemeralSecretUnavailable(t *testing.T) {
	previousReader := readTokenManagerSecret
	readTokenManagerSecret = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	defer func() { readTokenManagerSecret = previousReader }()

	manager := NewTokenManager("", time.Hour)
	if _, _, err := manager.SignWithClaims("user-1", "admin", "admin"); err == nil {
		t.Fatal("expected signing to fail when no secure token manager secret is available")
	}
	if _, err := manager.Verify("header.payload.signature"); err == nil {
		t.Fatal("expected verification to fail when no secure token manager secret is available")
	}
}

func TestTokenManagerUsesConfiguredSecretWhenEntropyUnavailable(t *testing.T) {
	previousReader := readTokenManagerSecret
	readTokenManagerSecret = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	defer func() { readTokenManagerSecret = previousReader }()

	manager := NewTokenManager("configured-secret", time.Hour)
	token, claims, err := manager.SignWithClaims("user-1", "admin", "admin")
	if err != nil {
		t.Fatalf("configured signing secret should remain usable: %v", err)
	}
	if claims == nil || claims.ID == "" {
		t.Fatalf("expected signed claims with token id, got %+v", claims)
	}
	verified, err := manager.Verify(token)
	if err != nil {
		t.Fatalf("configured signing secret should verify token: %v", err)
	}
	if verified.Subject != "user-1" || verified.Username != "admin" {
		t.Fatalf("unexpected verified claims: %+v", verified)
	}
}

func TestTokenManagerWithClockControlsSigningAndExpiryBoundary(t *testing.T) {
	issuedAt := time.Date(2024, time.March, 14, 15, 9, 26, 0, time.FixedZone("test", 8*60*60))
	clock := &middlewareFakeClock{now: issuedAt}
	manager := NewTokenManagerWithClock("configured-secret", time.Minute, clock)

	token, claims, err := manager.SignWithClaims("user-1", "admin", "admin")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	if claims.IssuedAt != issuedAt.UTC().Unix() {
		t.Fatalf("issued at = %d, want %d", claims.IssuedAt, issuedAt.UTC().Unix())
	}
	wantExpires := issuedAt.Add(time.Minute).UTC().Unix()
	if claims.Expires != wantExpires {
		t.Fatalf("expires = %d, want %d", claims.Expires, wantExpires)
	}

	clock.now = issuedAt.Add(time.Minute - time.Nanosecond)
	if _, err := manager.Verify(token); err != nil {
		t.Fatalf("token should remain valid immediately before expiry: %v", err)
	}

	clock.now = issuedAt.Add(time.Minute)
	if _, err := manager.Verify(token); err == nil {
		t.Fatal("expected token to expire exactly at its expiry boundary")
	}
}

func TestTokenManagerWithNilClockFallsBackToSystemClock(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	manager := NewTokenManagerWithClock("configured-secret", time.Hour, nil)
	_, claims, err := manager.SignWithClaims("user-1", "admin", "admin")
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	after := time.Now().UTC().Add(time.Second)
	issuedAt := time.Unix(claims.IssuedAt, 0).UTC()
	if issuedAt.Before(before) || issuedAt.After(after) {
		t.Fatalf("issued at = %s, want system time between %s and %s", issuedAt, before, after)
	}
}

func TestManagementAPIOrSessionMiddlewareWithClockSharesInjectedUTCClock(t *testing.T) {
	now := time.Date(2024, time.June, 1, 10, 30, 0, 0, time.FixedZone("test", -5*60*60))
	clock := &middlewareFakeClock{now: now}
	manager := NewTokenManagerWithClock("configured-secret", time.Hour, clock)
	sessionToken, _, err := manager.SignWithClaims("user-1", "admin", "admin")
	if err != nil {
		t.Fatalf("sign session token: %v", err)
	}
	validator := &recordingSessionValidator{active: true}
	var managementAt time.Time
	authenticate := func(raw string, at time.Time) (*Claims, func(), bool) {
		managementAt = at
		return &Claims{Subject: "api-token:fixture", ID: "fixture", Username: "fixture", Role: "api_token"}, nil, raw == ManagementAPITokenPrefix+"fixture"
	}
	handler := ManagementAPIOrSessionMiddlewareWithClock(manager, validator, authenticate, clock)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for name, token := range map[string]string{
		"session":    sessionToken,
		"management": ManagementAPITokenPrefix + "fixture",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
			}
		})
	}

	want := now.UTC()
	if len(validator.times) != 1 || !validator.times[0].Equal(want) || validator.times[0].Location() != time.UTC {
		t.Fatalf("session validation times = %v, want one UTC time %s", validator.times, want)
	}
	if !managementAt.Equal(want) || managementAt.Location() != time.UTC {
		t.Fatalf("management authentication time = %s (%s), want %s (UTC)", managementAt, managementAt.Location(), want)
	}
}

func TestManagementAPIAuthCleanupRunsBeforeBusinessHandler(t *testing.T) {
	released := false
	authenticate := func(string, time.Time) (*Claims, func(), bool) {
		return &Claims{Subject: "api-token:fixture", ID: "fixture"}, func() { released = true }, true
	}
	handler := ManagementAPIOrSessionMiddleware(nil, nil, authenticate)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !released {
			t.Fatal("authentication cleanup had not run before business handler")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/system", nil)
	req.Header.Set("Authorization", "Bearer "+ManagementAPITokenPrefix+"fixture")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestManagementAPITokenUsesFastDigestAndRetainsPrefixedBcryptCompatibility(t *testing.T) {
	raw := "cwapi_fixture_fast_digest"
	hash := HashManagementAPIToken(raw)
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("new token hash = %q, want sha256", hash)
	}
	now := time.Now().UTC()
	claims, ok := VerifyManagementAPIToken(raw, config.ManagementAPIConfig{Enabled: true, Tokens: []config.ManagementAPITokenConfig{{
		ID: "fast", Name: "fast", Prefix: "cwapi_fixt", Hash: hash, Scopes: []string{"read:system"}, Enabled: true,
	}}}, now)
	if !ok || claims == nil || claims.ID != "fast" {
		t.Fatalf("fast token verification failed: claims=%+v ok=%v", claims, ok)
	}

	legacyRaw := "cwapi_legacy_bcrypt_token"
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(legacyRaw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	claims, ok = VerifyManagementAPIToken(legacyRaw, config.ManagementAPIConfig{Enabled: true, Tokens: []config.ManagementAPITokenConfig{{
		ID: "legacy", Name: "legacy", Prefix: "cwapi_legac", Hash: "bcrypt:" + string(legacyHash), Scopes: []string{"read:system"}, Enabled: true,
	}}}, now)
	if !ok || claims == nil || claims.ID != "legacy" {
		t.Fatalf("legacy token verification failed: claims=%+v ok=%v", claims, ok)
	}
}

func TestManagementAPITokenRejectsHashMatchUnderWrongPrefix(t *testing.T) {
	raw := "cwapi_expected_token"
	claims, ok := VerifyManagementAPIToken(raw, config.ManagementAPIConfig{Enabled: true, Tokens: []config.ManagementAPITokenConfig{{
		ID: "wrong-prefix", Name: "wrong", Prefix: "cwapi_other", Hash: HashManagementAPIToken(raw), Scopes: []string{"read:system"}, Enabled: true,
	}}}, time.Now().UTC())
	if ok || claims != nil {
		t.Fatalf("token matched a record under the wrong lookup prefix: claims=%+v ok=%v", claims, ok)
	}
}

func TestSessionMiddlewareWithClockUsesInjectedUTCClock(t *testing.T) {
	now := time.Date(2024, time.September, 2, 8, 0, 0, 0, time.FixedZone("test", 9*60*60))
	clock := &middlewareFakeClock{now: now}
	validator := &recordingSessionValidator{active: true}
	handler := SessionMiddlewareWithClock(validator, clock)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/auth/refresh", nil)
	claims := &Claims{Subject: "user-1", ID: "session-1", Username: "admin", Role: "admin"}
	req = req.WithContext(context.WithValue(req.Context(), UserContextKey, claims))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, req)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	want := now.UTC()
	if len(validator.times) != 1 || !validator.times[0].Equal(want) || validator.times[0].Location() != time.UTC {
		t.Fatalf("session validation times = %v, want one UTC time %s", validator.times, want)
	}
}
