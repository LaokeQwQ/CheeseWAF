package captcha

import (
	"testing"
	"time"
)

func TestReceiptVerifiesClientModeAndExpiry(t *testing.T) {
	now := time.Date(2026, 6, 10, 6, 0, 0, 0, time.UTC)
	opts := ReceiptOptions{
		Secret:    "receipt-test-secret",
		Purpose:   "admin-login-receipt",
		ClientKey: "client-a",
		Path:      "admin-login",
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
	expired := opts
	expired.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if VerifyReceipt(expired, receipt, "slider") {
		t.Fatal("expired receipt verified")
	}
}
