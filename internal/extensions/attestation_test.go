package extensions

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestSignMarshalParseAndVerifyRiskHint(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	payload := []byte(`{"expires_at":"2026-10-04T12:05:00Z","observed_at":"2026-10-04T12:00:00Z","policy_epoch":17,"subject":{"site_ref":"site:demo","subject_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"api_version":"cheesewaf/risk-hint/v1"}`)
	signer := Signer{KeyID: "cheesewaf-host-output-v1", PrivateKey: private, Now: func() time.Time { return now }, MaxTTL: 10 * time.Minute}
	attested, err := signer.Sign(payload, now.Add(time.Second))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := json.Marshal(attested)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := Parse(wire)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Verify(parsed, map[string]TrustKey{attested.Integrity.KeyID: {ID: attested.Integrity.KeyID, PublicKey: private.Public().(ed25519.PublicKey)}}, VerifyOptions{
		Now: now.Add(2 * time.Second), MaxTTL: 10 * time.Minute, PolicyEpoch: 17, SiteRef: "site:demo",
		SubjectHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got := attested.Integrity.Domain; got != Domain {
		t.Fatalf("domain = %q, want %q", got, Domain)
	}
}

func TestVerifyRejectsTamperingAndReturnsAuditCode(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	signer := Signer{KeyID: "host-v1", PrivateKey: private, Now: func() time.Time { return now }}
	attested, err := signer.Sign([]byte(`{"api_version":"cheesewaf/risk-hint/v1","policy_epoch":1}`), now)
	if err != nil {
		t.Fatal(err)
	}
	attested.Payload = []byte(`{"api_version":"cheesewaf/risk-hint/v1","policy_epoch":2}`)
	err = Verify(attested, map[string]TrustKey{"host-v1": {ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey)}}, VerifyOptions{Now: now, PolicyEpoch: 1})
	if !errors.Is(err, ErrPayloadDigest) || AuditCode(err) != string(RejectPayloadDigest) {
		t.Fatalf("err = %v, code=%s, want digest rejection", err, AuditCode(err))
	}
}

func TestVerifyRejectsKeyLifecycleTTLPolicyAndScope(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	payload := []byte(`{"api_version":"cheesewaf/risk-hint/v1","policy_epoch":9,"observed_at":"2026-10-04T11:59:00Z","expires_at":"2026-10-04T12:30:00Z","subject":{"site_ref":"site:a","subject_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}`)
	signer := Signer{KeyID: "host-v1", PrivateKey: private, Now: func() time.Time { return now }, MaxTTL: time.Hour}
	attested, err := signer.Sign(payload, now)
	if err != nil {
		t.Fatal(err)
	}
	key := TrustKey{ID: "host-v1", PublicKey: private.Public().(ed25519.PublicKey), NotBefore: now.Add(time.Minute)}
	err = Verify(attested, map[string]TrustKey{"host-v1": key}, VerifyOptions{Now: now, PolicyEpoch: 9, SiteRef: "site:a"})
	if !errors.Is(err, ErrKeyOutsideValidity) {
		t.Fatalf("key window err = %v", err)
	}
	key.NotBefore = time.Time{}
	key.RevokedAt = ptrTime(now)
	err = Verify(attested, map[string]TrustKey{"host-v1": key}, VerifyOptions{Now: now, PolicyEpoch: 9, SiteRef: "site:a"})
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("revocation err = %v", err)
	}
	key.RevokedAt = nil
	err = Verify(attested, map[string]TrustKey{"host-v1": key}, VerifyOptions{Now: now, MaxTTL: 5 * time.Minute, PolicyEpoch: 9, SiteRef: "site:other"})
	if !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("ttl err = %v", err)
	}
	err = Verify(attested, map[string]TrustKey{"host-v1": key}, VerifyOptions{Now: now, MaxTTL: time.Hour, PolicyEpoch: 8, SiteRef: "site:a"})
	if !errors.Is(err, ErrPolicyEpochMismatch) {
		t.Fatalf("epoch err = %v", err)
	}
	err = Verify(attested, map[string]TrustKey{"host-v1": key}, VerifyOptions{Now: now, MaxTTL: time.Hour, PolicyEpoch: 9, SiteRef: "site:other"})
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("scope err = %v", err)
	}
}

func TestSignerRejectsNonCanonicalAndOverlongTTL(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	signer := Signer{KeyID: "host-v1", PrivateKey: private, Now: func() time.Time { return now }, MaxTTL: time.Minute}
	_, err = signer.Sign([]byte(`{"observed_at":"2026-10-04T12:00:00Z","expires_at":"2026-10-04T12:02:00Z"}`), now)
	if !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("ttl sign err = %v", err)
	}
	_, err = (Signer{KeyID: "host-v1", PrivateKey: private}).Sign([]byte(`[]`), now)
	if !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("array sign err = %v", err)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
