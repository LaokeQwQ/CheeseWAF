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
