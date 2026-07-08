package middleware

import (
	"errors"
	"testing"
	"time"
)

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
