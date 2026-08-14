package handler

import (
	"strings"
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
