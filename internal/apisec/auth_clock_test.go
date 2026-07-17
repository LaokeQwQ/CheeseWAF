package apisec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type authenticatorTestClock struct {
	now time.Time
}

func (c authenticatorTestClock) Now() time.Time {
	return c.now
}

func TestAuthenticatorUsesInjectedClock(t *testing.T) {
	want := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	authenticator, err := NewAuthenticatorWithClock(config.APISecConfig{}, authenticatorTestClock{now: want})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	defer authenticator.Close()
	if got := authenticator.now(); !got.Equal(want) {
		t.Fatalf("authenticator time = %s, want %s", got, want)
	}
}

func TestAuthenticatorRequiresAndEnforcesExp(t *testing.T) {
	const secret = "test-auth-secret"
	now := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	auth, err := NewAuthenticatorWithClock(config.APISecConfig{
		Auth: config.APIAuthConfig{
			Enabled:         true,
			JWTAlgorithms:   []string{"HS256"},
			JWTSharedSecret: secret,
		},
		Validation: config.APIValidationConfig{
			Schemas: []config.APIEndpointSchemaConfig{{
				ID: "orders", Method: "GET", PathPattern: "^/v1/orders$", Enabled: true,
			}},
		},
	}, authenticatorTestClock{now: now})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	defer auth.Close()

	reqMissing := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	// Build a signed token without exp by calling the low-level helper with a sentinel.
	reqMissing.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"exp": 0}))
	if finding := auth.Evaluate(reqMissing); finding == nil || finding.Field != "exp" {
		t.Fatalf("expected missing/zero exp finding, got %+v", finding)
	}

	reqExpired := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	reqExpired.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"exp": now.Unix()}))
	if finding := auth.Evaluate(reqExpired); finding == nil || finding.Field != "exp" || finding.Message != "API authorization token is expired" {
		t.Fatalf("expected boundary-expired finding, got %+v", finding)
	}

	reqValid := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	reqValid.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"exp": now.Add(time.Minute).Unix()}))
	if finding := auth.Evaluate(reqValid); finding != nil {
		t.Fatalf("expected valid exp to pass, got %+v", finding)
	}
}
