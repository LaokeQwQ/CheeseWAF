package passkey

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestChallengeTokenRoundTrip(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	user := User{ID: "admin", Name: "Administrator"}

	creation, token, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	if token == "" {
		t.Fatal("BeginRegistration() returned an empty token")
	}

	if creation.Response.RelyingParty.ID != "example.com" {
		t.Fatalf("RP ID = %q", creation.Response.RelyingParty.ID)
	}

	session, err := service.openSession(context.Background(), token, CeremonyRegistration, user.ID)
	if err != nil {
		t.Fatalf("openSession() error = %v", err)
	}

	if session.Challenge != creation.Response.Challenge.String() {
		t.Fatalf("challenge = %q, want %q", session.Challenge, creation.Response.Challenge.String())
	}

	if string(session.UserID) != user.ID {
		t.Fatalf("session user ID = %q", session.UserID)
	}

	if session.RelyingPartyID != "example.com" {
		t.Fatalf("session RP ID = %q", session.RelyingPartyID)
	}

	wantExpiry := testNow.Add(2 * time.Minute)
	if !session.Expires.Equal(wantExpiry) {
		t.Fatalf("session expires = %s, want %s", session.Expires, wantExpiry)
	}
}

func TestChallengeTokenRejectsTampering(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	user := User{ID: "admin", Name: "Administrator"}

	_, token, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}

	t.Run("mac byte", func(t *testing.T) {
		tampered := append([]byte(nil), raw...)
		tampered[len(tampered)-1] ^= 0xff

		_, err := service.openSession(context.Background(), base64.RawURLEncoding.EncodeToString(tampered), CeremonyRegistration, user.ID)
		if !errors.Is(err, ErrInvalidSessionToken) {
			t.Fatalf("openSession() error = %v, want ErrInvalidSessionToken", err)
		}
	})

	t.Run("payload byte", func(t *testing.T) {
		tampered := append([]byte(nil), raw...)
		tampered[40] ^= 0x01

		_, err := service.openSession(context.Background(), base64.RawURLEncoding.EncodeToString(tampered), CeremonyRegistration, user.ID)
		if !errors.Is(err, ErrInvalidSessionToken) {
			t.Fatalf("openSession() error = %v, want ErrInvalidSessionToken", err)
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := service.openSession(context.Background(), "not-a-token", CeremonyRegistration, user.ID); !errors.Is(err, ErrInvalidSessionToken) {
			t.Fatalf("openSession() error = %v, want ErrInvalidSessionToken", err)
		}

		oversized := strings.Repeat("A", sessionTokenMaxEncodedBytes+1)
		if _, err := service.openSession(context.Background(), oversized, CeremonyRegistration, user.ID); !errors.Is(err, ErrInvalidSessionToken) {
			t.Fatalf("openSession() oversized error = %v, want ErrInvalidSessionToken", err)
		}
	})

	t.Run("different signing key", func(t *testing.T) {
		other, err := NewService(validConfig(), Options{
			Store:      newMemoryStore(),
			SessionKey: []byte(strings.Repeat("z", MinSessionKeyLen)),
			Now:        clock.Now,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}

		if _, err := other.openSession(context.Background(), token, CeremonyRegistration, user.ID); !errors.Is(err, ErrInvalidSessionToken) {
			t.Fatalf("openSession() error = %v, want ErrInvalidSessionToken", err)
		}
	})
}

func TestChallengeTokenExpires(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	user := User{ID: "admin", Name: "Administrator"}

	_, token, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	clock.Advance(2 * time.Minute)

	if _, err := service.openSession(context.Background(), token, CeremonyRegistration, user.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("openSession() error = %v, want ErrSessionExpired", err)
	}
}

func TestChallengeTokenSingleUse(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	user := User{ID: "admin", Name: "Administrator"}

	_, token, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	if _, err := service.openSession(context.Background(), token, CeremonyRegistration, user.ID); err != nil {
		t.Fatalf("first openSession() error = %v", err)
	}

	if _, err := service.openSession(context.Background(), token, CeremonyRegistration, user.ID); !errors.Is(err, ErrSessionReplayed) {
		t.Fatalf("second openSession() error = %v, want ErrSessionReplayed", err)
	}
}

func TestChallengeTokenBindsCeremonyAndUser(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	user := User{ID: "admin", Name: "Administrator"}

	_, token, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	if _, err := service.openSession(context.Background(), token, CeremonyLogin, user.ID); !errors.Is(err, ErrCeremonyMismatch) {
		t.Fatalf("ceremony mismatch error = %v, want ErrCeremonyMismatch", err)
	}

	if _, err := service.openSession(context.Background(), token, CeremonyRegistration, "other"); !errors.Is(err, ErrUserMismatch) {
		t.Fatalf("user mismatch error = %v, want ErrUserMismatch", err)
	}

	// Rejected tokens are not consumed.
	if _, err := service.openSession(context.Background(), token, CeremonyRegistration, user.ID); err != nil {
		t.Fatalf("openSession() after rejected attempts error = %v", err)
	}
}

func TestBeginLoginRequiresCredentialsAndIssuesLoginToken(t *testing.T) {
	store := newMemoryStore()
	clock := newTestClock()
	service := newTestService(t, store, clock)
	user := User{ID: "admin", Name: "Administrator"}

	if _, _, err := service.BeginLogin(context.Background(), user); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("BeginLogin() error = %v, want ErrNoCredentials", err)
	}

	credential := testCredential(user.ID, 1)
	if err := store.Create(context.Background(), credential); err != nil {
		t.Fatalf("store.Create() error = %v", err)
	}

	assertion, token, err := service.BeginLogin(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	if len(assertion.Response.AllowedCredentials) != 1 {
		t.Fatalf("allowed credentials = %d, want 1", len(assertion.Response.AllowedCredentials))
	}

	session, err := service.openSession(context.Background(), token, CeremonyLogin, user.ID)
	if err != nil {
		t.Fatalf("openSession() error = %v", err)
	}

	if len(session.AllowedCredentialIDs) != 1 {
		t.Fatalf("session allowed credential IDs = %d, want 1", len(session.AllowedCredentialIDs))
	}
}

func TestBeginRegistrationRejectsInvalidUser(t *testing.T) {
	service := newTestService(t, newMemoryStore(), newTestClock())

	tests := []User{
		{},
		{ID: "admin"},
		{ID: "", Name: "Administrator"},
		{ID: strings.Repeat("a", MaxUserIDLen+1), Name: "Administrator"},
	}

	for _, user := range tests {
		if _, _, err := service.BeginRegistration(context.Background(), user); !errors.Is(err, ErrInvalidUser) {
			t.Fatalf("BeginRegistration(%q, %q) error = %v, want ErrInvalidUser", user.ID, user.Name, err)
		}
	}
}

func TestMemoryReplayGuardBoundAndExpiry(t *testing.T) {
	guard := NewMemoryReplayGuard(2)
	now := testNow
	expires := now.Add(time.Minute)

	var first [16]byte
	first[0] = 1
	var second [16]byte
	second[0] = 2
	var third [16]byte
	third[0] = 3

	if ok, err := guard.Consume(first, now, expires); err != nil || !ok {
		t.Fatalf("first Consume() = %v, %v", ok, err)
	}

	if ok, err := guard.Consume(first, now, expires); err != nil || ok {
		t.Fatalf("replayed Consume() = %v, %v", ok, err)
	}

	if ok, err := guard.Consume(second, now, expires); err != nil || !ok {
		t.Fatalf("second Consume() = %v, %v", ok, err)
	}

	if _, err := guard.Consume(third, now, expires); !errors.Is(err, ErrReplayGuardFull) {
		t.Fatalf("full guard error = %v, want ErrReplayGuardFull", err)
	}

	if ok, err := guard.Consume(third, expires.Add(time.Second), expires); err != nil || !ok {
		t.Fatalf("Consume() after expiry = %v, %v", ok, err)
	}
}
