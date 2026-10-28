package extensions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMemorySignerProviderRotatesWithoutPrivateKeySnapshot(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	pub1, private1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, private2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewMemorySignerProvider(MemorySignerProviderOptions{
		Keys:        []MemorySignerKey{{ID: "host-v1", PrivateKey: private1}, {ID: "host-v2", PrivateKey: private2, NotBefore: now.Add(time.Minute)}},
		ActiveKeyID: "host-v1", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	snapshot, err := p.TrustSnapshot(context.Background())
	if err != nil || snapshot.ActiveKeyID != "host-v1" || snapshot.Generation != 1 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "private") || strings.Contains(string(encoded), "seed") {
		t.Fatalf("private material leaked in snapshot: %s", encoded)
	}
	if !ed25519.PublicKey(snapshot.Keys["host-v1"].PublicKey).Equal(pub1) {
		t.Fatal("snapshot public key mismatch")
	}
	out, err := p.Sign(context.Background(), []byte(`{"api_version":"cheesewaf/risk-hint/v1","policy_epoch":1}`), now)
	if err != nil || out.Integrity.KeyID != "host-v1" {
		t.Fatalf("sign=%+v err=%v", out, err)
	}
	if err := p.Rotate(context.Background(), "host-v2"); !errors.Is(err, ErrKeyOutsideValidity) {
		t.Fatalf("future rotation err=%v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := p.Rotate(context.Background(), "host-v2"); err != nil {
		t.Fatalf("rotation err=%v", err)
	}
	snapshot, err = p.TrustSnapshot(context.Background())
	if err != nil || snapshot.ActiveKeyID != "host-v2" || snapshot.Generation != 2 {
		t.Fatalf("rotated snapshot=%+v err=%v", snapshot, err)
	}
	out, err = p.Sign(context.Background(), []byte(`{"api_version":"cheesewaf/risk-hint/v1","policy_epoch":1}`), now)
	if err != nil || out.Integrity.KeyID != "host-v2" {
		t.Fatalf("rotated sign=%+v err=%v", out, err)
	}
	keys := snapshot.Keys
	if err := Verify(out, keys, VerifyOptions{Now: now, PolicyEpoch: 1}); err != nil {
		t.Fatalf("rotated output verify: %v", err)
	}
}

func TestMemorySignerProviderRevocationAndValidityBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewMemorySignerProvider(MemorySignerProviderOptions{
		Keys: []MemorySignerKey{{ID: "host-v1", PrivateKey: private, NotAfter: now.Add(time.Minute)}}, ActiveKeyID: "host-v1", Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	payload := []byte(`{"api_version":"cheesewaf/risk-hint/v1","policy_epoch":1}`)
	now = now.Add(time.Minute)
	if _, err := provider.Sign(context.Background(), payload, now); !errors.Is(err, ErrKeyOutsideValidity) {
		t.Fatalf("not-after boundary err=%v", err)
	}
	now = now.Add(-time.Second)
	if err := provider.Revoke(context.Background(), "host-v1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Sign(context.Background(), payload, now); !errors.Is(err, ErrSignerNoActiveKey) {
		t.Fatalf("revoked sign err=%v", err)
	}
	snapshot, err := provider.TrustSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ActiveKeyID != "" || snapshot.Keys["host-v1"].RevokedAt == nil {
		t.Fatalf("revoked snapshot=%+v", snapshot)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.TrustSnapshot(context.Background()); !errors.Is(err, ErrSignerProviderClosed) {
		t.Fatalf("closed snapshot err=%v", err)
	}
}

func TestMemorySignerProviderContextCancellationAndConfigBoundaries(t *testing.T) {
	if _, err := NewMemorySignerProvider(MemorySignerProviderOptions{}); !errors.Is(err, ErrSignerKeyNotUsable) {
		t.Fatalf("empty config err=%v", err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewMemorySignerProvider(MemorySignerProviderOptions{Keys: []MemorySignerKey{{ID: "host-v1", PrivateKey: private}}, ActiveKeyID: "host-v1"})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.TrustSnapshot(ctx); err == nil {
		t.Fatal("cancelled snapshot was accepted")
	}
	if err := p.Rotate(ctx, "host-v1"); err == nil {
		t.Fatal("cancelled rotation was accepted")
	}
}
