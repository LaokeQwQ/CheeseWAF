package handler

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifyTOTP(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0)
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	if !verifyTOTP(secret, code, now) {
		t.Fatal("expected generated TOTP code to verify")
	}
	if verifyTOTP(secret, "000000", now) && code != "000000" {
		t.Fatal("expected invalid TOTP code to be rejected")
	}
	if verifyTOTP(secret, "not-code", now) {
		t.Fatal("expected non-numeric TOTP code to be rejected")
	}
}

func TestTOTPURL(t *testing.T) {
	uri := totpURL("admin@example.test", "ABCDEF")
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("unexpected TOTP uri: %s", uri)
	}
}

func TestConsumeTOTPRejectsReuseInSameWindow(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	state := newTwoFAState()
	if !state.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("first consume of a valid code must succeed")
	}
	if state.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("second consume of the same code in the same window must fail")
	}
}

func TestConsumeTOTPAllowsDifferentCounters(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code1, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	state := newTwoFAState()
	if !state.consumeTOTP("user-1", secret, code1, now) {
		t.Fatal("first window consume must succeed")
	}
	// Advance by two periods so the matching step is outside the prior ±1 window.
	later := now.Add(2 * time.Duration(totpPeriod) * time.Second)
	code2, err := hotp(secret, later.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp later: %v", err)
	}
	if !state.consumeTOTP("user-1", secret, code2, later) {
		t.Fatal("consume at a new counter must succeed")
	}
}

func TestConsumeTOTPAllowsSameCodeForDifferentUsers(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	state := newTwoFAState()
	if !state.consumeTOTP("user-a", secret, code, now) {
		t.Fatal("first user consume must succeed")
	}
	if !state.consumeTOTP("user-b", secret, code, now) {
		t.Fatal("different userID must not share consume slot")
	}
}

func TestConsumeTOTPInvalidCodeDoesNotOccupySlot(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	state := newTwoFAState()
	if state.consumeTOTP("user-1", secret, "000000", now) && code != "000000" {
		t.Fatal("invalid code must not consume")
	}
	if !state.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("valid code must still consume after a failed invalid attempt")
	}
}

func TestConsumeTOTPReleaseAllowsReuse(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	state := newTwoFAState()
	counter, ok := state.consumeTOTPCounter("user-1", secret, code, now)
	if !ok {
		t.Fatal("first consume must succeed")
	}
	state.releaseConsumedTOTP("user-1", counter)
	if !state.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("released consume slot must allow the same step again")
	}
}

type fakeTOTPStore struct {
	mu       sync.Mutex
	consumed map[string]time.Time
}

func (f *fakeTOTPStore) MarkTOTPConsumed(_ context.Context, userID string, counter int64, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consumed == nil {
		f.consumed = map[string]time.Time{}
	}
	f.consumed[totpConsumeKey(userID, counter)] = expiresAt
	return nil
}

func (f *fakeTOTPStore) IsTOTPConsumed(_ context.Context, userID string, counter int64, now time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	expiresAt, ok := f.consumed[totpConsumeKey(userID, counter)]
	return ok && expiresAt.After(now), nil
}

func (f *fakeTOTPStore) DeleteTOTPConsumed(_ context.Context, userID string, counter int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.consumed, totpConsumeKey(userID, counter))
	return nil
}

func (f *fakeTOTPStore) PruneTOTPConsumed(_ context.Context, before time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, expiresAt := range f.consumed {
		if !expiresAt.After(before) {
			delete(f.consumed, key)
		}
	}
	return nil
}

func TestConsumeTOTPRefusesReplayAfterRestart(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	store := &fakeTOTPStore{}
	first := newTwoFAStateWithStore(store)
	if !first.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("first consume of a valid code must succeed")
	}
	// Simulate a process restart: a brand new twoFAState shares the same
	// persisted consumed-counters store, so the burned code must be rejected.
	second := newTwoFAStateWithStore(store)
	if second.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("same code must be rejected after restart replay")
	}
}

func TestConsumeTOTPAllowsReuseAfterTTL(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0).UTC()
	code, err := hotp(secret, now.Unix()/totpPeriod)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	store := &fakeTOTPStore{}
	state := newTwoFAStateWithStore(store)
	// Use a short TTL equal to one TOTP period so we can validate that an
	// expired consumed record no longer blocks the same code while it is still
	// inside the ±1 window.
	state.consumedTTL = time.Duration(totpPeriod) * time.Second
	if !state.consumeTOTP("user-1", secret, code, now) {
		t.Fatal("first consume must succeed")
	}
	later := now.Add(time.Duration(totpPeriod)*time.Second + time.Second)
	if !state.consumeTOTP("user-1", secret, code, later) {
		t.Fatal("expected expired consumed record to allow same code reuse")
	}
}
