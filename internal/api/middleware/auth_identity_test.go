package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
)

func TestTokenManagerRejectsNonCanonicalHumanUsernameAtSigning(t *testing.T) {
	manager := NewTokenManager("configured-secret", time.Hour)
	for _, username := range []string{" admin", "admin ", "ad\tmin", "ad\u200bmin"} {
		t.Run(username, func(t *testing.T) {
			if _, _, err := manager.SignWithClaims("user-1", username, "admin"); !errors.Is(err, identity.ErrInvalidUsername) {
				t.Fatalf("SignWithClaims(%q) error = %v, want ErrInvalidUsername", username, err)
			}
		})
	}
}

func TestTokenManagerRejectsAlreadySignedNonCanonicalHumanUsername(t *testing.T) {
	now := time.Date(2026, time.September, 7, 10, 0, 0, 0, time.UTC)
	manager := NewTokenManagerWithClock("configured-secret", time.Hour, &middlewareFakeClock{now: now})
	claims := Claims{
		Subject:  "user-1",
		ID:       "session-1",
		Username: "admin\u200b",
		Role:     "admin",
		IssuedAt: now.Unix(),
		Expires:  now.Add(time.Hour).Unix(),
	}
	token := signTestJWT(t, manager, map[string]string{"alg": "HS256", "typ": "JWT"}, claims)

	if _, err := manager.Verify(token); !errors.Is(err, identity.ErrInvalidUsername) {
		t.Fatalf("Verify() error = %v, want ErrInvalidUsername", err)
	}
}

func TestTokenManagerAllowsAPITokenDisplayName(t *testing.T) {
	manager := NewTokenManager("configured-secret", time.Hour)
	token, claims, err := manager.SignWithClaims("api-token:deploy", "Production Deploy Token", "api_token")
	if err != nil {
		t.Fatalf("SignWithClaims() rejected API token display name: %v", err)
	}
	if claims.Username != "Production Deploy Token" {
		t.Fatalf("signed display name = %q, want exact value", claims.Username)
	}
	verified, err := manager.Verify(token)
	if err != nil {
		t.Fatalf("Verify() rejected API token display name: %v", err)
	}
	if verified.Username != "Production Deploy Token" {
		t.Fatalf("verified display name = %q, want exact value", verified.Username)
	}
}

func TestSessionMiddlewareRejectsNonCanonicalHumanUsernameBeforeStoreLookup(t *testing.T) {
	validator := &recordingSessionValidator{active: true}
	handler := SessionMiddleware(validator)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/auth/refresh", nil)
	request = request.WithContext(context.WithValue(request.Context(), UserContextKey, &Claims{
		Subject:  "user-1",
		ID:       "session-1",
		Username: " admin",
		Role:     "admin",
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if len(validator.times) != 0 {
		t.Fatalf("session store queried for invalid username: %v", validator.times)
	}
}
