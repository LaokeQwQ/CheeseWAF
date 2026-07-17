package captcha

import (
	"strings"
	"testing"
	"time"
)

func TestReceiptRejectsOversizedInput(t *testing.T) {
	opts := ReceiptOptions{Secret: "receipt-test-secret", ClientKey: "client", Subject: "Cheese"}
	if VerifyReceipt(opts, strings.Repeat("x", receiptMaxEncodedBytes+1), "slider") {
		t.Fatal("oversized receipt verified")
	}
}

func TestReceiptVerifiesClientModeAndExpiry(t *testing.T) {
	now := time.Date(2026, 6, 10, 6, 0, 0, 0, time.UTC)
	opts := ReceiptOptions{
		Secret:    "receipt-test-secret",
		Purpose:   "admin-login-receipt",
		ClientKey: "client-a",
		Path:      "admin-login",
		Subject:   "Cheese",
		TTL:       time.Minute,
		Now:       func() time.Time { return now },
	}
	receipt, _, err := NewReceipt(opts, "slider")
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}
	if !VerifyReceipt(opts, receipt, "slider") {
		t.Fatal("expected receipt to verify")
	}
	otherClient := opts
	otherClient.ClientKey = "client-b"
	if VerifyReceipt(otherClient, receipt, "slider") {
		t.Fatal("receipt verified for a different client")
	}
	if VerifyReceipt(opts, receipt, "pow") {
		t.Fatal("receipt verified for a different captcha mode")
	}
	otherSubject := opts
	otherSubject.Subject = "another-user"
	if VerifyReceipt(otherSubject, receipt, "slider") {
		t.Fatal("receipt verified for a different username")
	}
	sameSubject := opts
	sameSubject.Subject = "  cheese  "
	if !VerifyReceipt(sameSubject, receipt, "slider") {
		t.Fatal("normalized username should verify")
	}
	expired := opts
	expired.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if VerifyReceipt(expired, receipt, "slider") {
		t.Fatal("expired receipt verified")
	}
}

func TestReceiptKeepsMillisecondExpiryPrecision(t *testing.T) {
	now := time.Date(2026, 6, 10, 6, 0, 0, int(100*time.Millisecond), time.UTC)
	opts := ReceiptOptions{Secret: "receipt-test-secret", ClientKey: "client", Subject: "Cheese", TTL: 1500 * time.Millisecond, Now: func() time.Time { return now }}
	receipt, expires, err := NewReceipt(opts, "slider")
	if err != nil {
		t.Fatal(err)
	}
	opts.Now = func() time.Time { return expires.Add(-time.Millisecond) }
	if !VerifyReceipt(opts, receipt, "slider") {
		t.Fatal("receipt expired before its millisecond deadline")
	}
	opts.Now = func() time.Time { return expires }
	if VerifyReceipt(opts, receipt, "slider") {
		t.Fatal("receipt remained valid at its deadline")
	}
}
