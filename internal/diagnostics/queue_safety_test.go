package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func queueRequest(key string) Request {
	return Request{Package: Package{Kind: KindHealth, Health: map[string]string{"status": "ok"}}, Target: "test/audit", PluginID: "health", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "lease-1", IdempotencyKey: key}
}

func TestUploadingItemsRemainWithinQueueCapacity(t *testing.T) {
	b, err := NewBroker(Config{MaxQueueItems: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Submit(context.Background(), queueRequest("first")); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Next(); !ok {
		t.Fatal("missing upload")
	}
	if _, err := b.Submit(context.Background(), queueRequest("second")); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("uploading task did not reserve capacity: %v", err)
	}
}

func TestExpiryFreesQueuedSlotWithoutWorkerPoll(t *testing.T) {
	now := time.Unix(100, 0)
	b, err := NewBroker(Config{MaxQueueItems: 1, TTL: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := b.Submit(context.Background(), queueRequest("old"))
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	second, err := b.Submit(context.Background(), queueRequest("new"))
	if err != nil {
		t.Fatalf("expired queued item still blocks submission: %v", err)
	}
	if first.UploadID == second.UploadID {
		t.Fatal("expired ID reused")
	}
	item, ok := b.Next()
	if !ok || item.UploadID != second.UploadID {
		t.Fatalf("worker received stale item: %+v, %v", item, ok)
	}
}

func TestTerminalItemsDropPayloadAndBoundHistory(t *testing.T) {
	b, err := NewBroker(Config{MaxQueueItems: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		receipt, err := b.Submit(context.Background(), queueRequest(fmt.Sprint(i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := b.Next(); !ok {
			t.Fatal("missing item")
		}
		if err := b.Complete(receipt.UploadID, true); err != nil {
			t.Fatal(err)
		}
		record := b.records[receipt.UploadID]
		if record != nil && (record.item.Package.Health != nil || record.item.Package.Metadata != nil || record.item.Package.Findings != nil) {
			t.Fatal("completed payload retained after bytes quota was released")
		}
	}
	if b.bytes != 0 {
		t.Fatalf("residual byte accounting: %d", b.bytes)
	}
	if len(b.records) > 4 || len(b.idempotency) > 4 {
		t.Fatalf("unbounded records/idempotency: %d/%d", len(b.records), len(b.idempotency))
	}
}

func TestExpiredIdempotencyDoesNotReturnSuccessReceipt(t *testing.T) {
	now := time.Unix(100, 0)
	b, err := NewBroker(Config{TTL: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	request := queueRequest("same")
	if _, err := b.Submit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := b.Submit(context.Background(), request); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired idempotency returned success: %v", err)
	}
}

func TestRetryByteAccountingReturnsToZeroAfterSuccess(t *testing.T) {
	b, err := NewBroker(Config{})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := b.Submit(context.Background(), queueRequest("retry"))
	if err != nil {
		t.Fatal(err)
	}
	b.Next()
	if err := b.Complete(receipt.UploadID, false); err != nil {
		t.Fatal(err)
	}
	if err := b.Retry(receipt.UploadID); err != nil {
		t.Fatal(err)
	}
	b.Next()
	if err := b.Complete(receipt.UploadID, true); err != nil {
		t.Fatal(err)
	}
	if b.bytes != 0 {
		t.Fatalf("leaked bytes after retry+complete: %d", b.bytes)
	}
}

func TestRawDiagnosticAttemptsCannotExceedTwo(t *testing.T) {
	b, err := NewBroker(Config{MaxAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	req := queueRequest("raw")
	req.Package.Kind = KindRaw
	req.ConfirmationID, req.PasswordConfirmed, req.FinalConfirmation, req.HighRiskAcknowledged = "confirmed", true, true, true
	receipt, err := b.Submit(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	b.Next()
	if err := b.Complete(receipt.UploadID, false); err != nil {
		t.Fatal(err)
	}
	if err := b.Retry(receipt.UploadID); err != nil {
		t.Fatal(err)
	}
	b.Next()
	if err := b.Complete(receipt.UploadID, false); !errors.Is(err, ErrAttemptsExceeded) {
		t.Fatalf("raw upload exceeded two attempts: %v", err)
	}
}

func TestAttemptsConfigCannotRaisePlatformMaximum(t *testing.T) {
	if _, err := NewBroker(Config{MaxAttempts: 4}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("attempt ceiling configurable above three: %v", err)
	}
}
