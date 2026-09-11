package diagnostics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDecodePackageRejectsUnknownFieldsAndForbiddenValues(t *testing.T) {
	if _, err := DecodePackage([]byte("{\"kind\":\"sanitized\",\"unexpected\":true}")); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
	if _, err := DecodePackage([]byte("{\"kind\":\"sanitized\",\"metadata\":{\"note\":\"Authorization: Bearer x\"}}")); !errors.Is(err, ErrForbiddenField) {
		t.Fatalf("err=%v", err)
	}
	if _, err := DecodePackage([]byte("{\"kind\":\"sanitized\",\"metadata\":{\"service\":\"edge\"}} trailing")); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing JSON err=%v", err)
	}
}

func TestSubmitSanitizedDiagnosticReturnsUploadIDAndQueues(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	b, err := NewBroker(Config{MaxQueueItems: 2, MaxQueueBytes: 1024, TTL: time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Submit(context.Background(), Request{Package: Package{Kind: KindSanitized, Metadata: map[string]string{"service": "edge"}, Health: map[string]string{"status": "ok"}}, Target: "tenant/audit", PluginID: "diag", PluginVersion: "1.2.3", PolicyEpoch: 7, LeaseID: "lease-1", IdempotencyKey: "idem-1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.UploadID == "" || r.State != StateQueued {
		t.Fatalf("unexpected receipt: %#v", r)
	}
	item, ok := b.Next()
	if !ok || item.UploadID != r.UploadID {
		t.Fatalf("next item = %#v, %v", item, ok)
	}
	if _, ok := b.Next(); ok {
		t.Fatal("queue should be empty")
	}
}

func TestSubmitRejectsForbiddenFieldsAndRawWithoutThreeConfirmations(t *testing.T) {
	b, err := NewBroker(Config{MaxQueueItems: 1, MaxQueueBytes: 1024, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		req  Request
		want error
	}{
		{name: "forbidden secret", req: Request{Package: Package{Kind: KindSanitized, Metadata: map[string]string{"token": "x"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "a"}, want: ErrForbiddenField},
		{name: "raw gate", req: Request{Package: Package{Kind: KindRaw, Metadata: map[string]string{"error": "trace"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "b", ConfirmationID: "c", PasswordConfirmed: true}, want: ErrRawConfirmationRequired},
		{name: "forbidden secret value", req: Request{Package: Package{Kind: KindSanitized, Metadata: map[string]string{"error": "Authorization: Bearer secret-token"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "c"}, want: ErrForbiddenField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.Submit(context.Background(), tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestRawRequiresHighRiskConfirmationAndExpiry(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	b, err := NewBroker(Config{MaxQueueItems: 2, MaxQueueBytes: 4096, TTL: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Package: Package{Kind: KindRaw, Metadata: map[string]string{"error": "trace"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "raw", ConfirmationID: "c", PasswordConfirmed: true, FinalConfirmation: true, HighRiskAcknowledged: true}
	r, err := b.Submit(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := b.Status(r.UploadID); !errors.Is(err, ErrExpired) {
		t.Fatalf("status err=%v", err)
	}
}

func TestIdempotencyBindsSecurityContextAndQuotas(t *testing.T) {
	b, err := NewBroker(Config{MaxQueueItems: 1, MaxQueueBytes: 256, TTL: time.Hour, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Package: Package{Kind: KindMetadata, Metadata: map[string]string{"a": "b"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "same"}
	a, err := b.Submit(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	bis, err := b.Submit(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if a.UploadID != bis.UploadID {
		t.Fatal("idempotent submit must return same upload")
	}
	req.PolicyEpoch = 2
	if _, err := b.Submit(context.Background(), req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("err=%v", err)
	}
	if _, err := b.Submit(context.Background(), Request{Package: Package{Kind: KindMetadata, Metadata: map[string]string{"long": "value"}}, Target: "t2", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l2", IdempotencyKey: "other"}); !errors.Is(err, ErrQueueFull) && !errors.Is(err, ErrByteQuota) {
		t.Fatalf("quota err=%v", err)
	}
}

func TestRetryStateIsBoundedByAttempts(t *testing.T) {
	b, err := NewBroker(Config{MaxQueueItems: 2, MaxQueueBytes: 4096, TTL: time.Hour, MaxAttempts: 2})
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Submit(context.Background(), Request{Package: Package{Kind: KindHealth, Health: map[string]string{"status": "ok"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "x"})
	if err != nil {
		t.Fatal(err)
	}
	item, _ := b.Next()
	if item.Attempt != 1 {
		t.Fatalf("attempt=%d", item.Attempt)
	}
	if err := b.Complete(r.UploadID, false); err != nil {
		t.Fatal(err)
	}
	s, _ := b.Status(r.UploadID)
	if s.State != StateRetrying || s.Attempt != 1 {
		t.Fatalf("status=%#v", s)
	}
	if err := b.Retry(r.UploadID); err != nil {
		t.Fatal(err)
	}
	item, _ = b.Next()
	if item.Attempt != 2 {
		t.Fatalf("attempt=%d", item.Attempt)
	}
	if err := b.Complete(r.UploadID, false); !errors.Is(err, ErrAttemptsExceeded) {
		t.Fatalf("err=%v", err)
	}
}

func TestRetryDoesNotDoubleCountQueuedBytes(t *testing.T) {
	b, err := NewBroker(Config{MaxQueueItems: 2, MaxQueueBytes: 4096, TTL: time.Hour, MaxAttempts: 3})
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Submit(context.Background(), Request{Package: Package{Kind: KindHealth, Health: map[string]string{"status": "ok"}}, Target: "t", PluginID: "p", PluginVersion: "1.0.0", PolicyEpoch: 1, LeaseID: "l", IdempotencyKey: "retry-bytes"})
	if err != nil {
		t.Fatal(err)
	}
	item, ok := b.Next()
	if !ok {
		t.Fatal("missing queued item")
	}
	if err := b.Complete(r.UploadID, false); err != nil {
		t.Fatal(err)
	}
	if err := b.Retry(r.UploadID); err != nil {
		t.Fatal(err)
	}
	if b.bytes != item.Bytes {
		t.Fatalf("retry changed accounted bytes from %d to %d", item.Bytes, b.bytes)
	}
}
