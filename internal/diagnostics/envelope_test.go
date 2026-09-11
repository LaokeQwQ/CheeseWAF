package diagnostics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type testKeyWrapper struct {
	keys      map[string][]byte
	wrapErr   error
	unwrapErr error
}

func (w testKeyWrapper) Wrap(_ context.Context, version string, dek []byte) ([]byte, error) {
	if w.wrapErr != nil {
		return nil, w.wrapErr
	}
	key := w.keys[version]
	out := make([]byte, len(dek))
	for i := range dek {
		out[i] = dek[i] ^ key[i%len(key)]
	}
	return out, nil
}

func (w testKeyWrapper) Unwrap(_ context.Context, version string, wrapped []byte) ([]byte, error) {
	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}
	return w.Wrap(context.Background(), version, wrapped)
}

func TestSealAndOpenDiagnosticEnvelope(t *testing.T) {
	meta := EnvelopeMetadata{
		TenantID:      "tenant-a",
		PluginID:      "diag",
		PluginVersion: "1.2.3",
		Target:        "tenant/audit",
		PolicyEpoch:   7,
	}
	payload := []byte(`{"kind":"sanitized"}`)
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("test-key")}}
	envelope, err := SealEnvelope(context.Background(), payload, meta, "kek-v1", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := OpenEnvelope(context.Background(), envelope, wrapper); err != nil || string(got) != string(payload) {
		t.Fatalf("open=%q err=%v", got, err)
	}
	digest := sha256.Sum256(payload)
	if envelope.Metadata.SHA256Digest != hex.EncodeToString(digest[:]) {
		t.Fatalf("digest=%q", envelope.Metadata.SHA256Digest)
	}
}

func TestEachEnvelopeUsesIndependentDEKAndContainsNoPlaintext(t *testing.T) {
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("test-key")}}
	meta := EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit", PolicyEpoch: 1}
	payload := []byte("diagnostic secret-shaped payload")
	a, err := SealEnvelope(context.Background(), payload, meta, "kek-v1", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealEnvelope(context.Background(), payload, meta, "kek-v1", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("separate packages must not reuse DEK/ciphertext")
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, payload) {
		t.Fatal("serialized envelope must not contain plaintext")
	}
}

func TestEnvelopeAADAndDigestRejectTampering(t *testing.T) {
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("test-key")}}
	meta := EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit", PolicyEpoch: 1}
	envelope, err := SealEnvelope(context.Background(), []byte("payload"), meta, "kek-v1", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*EnvelopeMetadata)
	}{
		{name: "tenant", mutate: func(m *EnvelopeMetadata) { m.TenantID = "other-tenant" }},
		{name: "plugin", mutate: func(m *EnvelopeMetadata) { m.PluginID = "other-plugin" }},
		{name: "version", mutate: func(m *EnvelopeMetadata) { m.PluginVersion = "2.0.0" }},
		{name: "target", mutate: func(m *EnvelopeMetadata) { m.Target = "other-target" }},
		{name: "digest", mutate: func(m *EnvelopeMetadata) { m.SHA256Digest = strings.Repeat("a", 64) }},
		{name: "policy epoch", mutate: func(m *EnvelopeMetadata) { m.PolicyEpoch++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			tampered := envelope
			mutation.mutate(&tampered.Metadata)
			if err := VerifyEnvelope(context.Background(), tampered, wrapper); !errors.Is(err, ErrEnvelopeAuthentication) {
				t.Fatalf("metadata tamper err=%v", err)
			}
		})
	}
	if _, err := SealEnvelope(context.Background(), []byte("payload"), EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit", PolicyEpoch: 1, SHA256Digest: strings.Repeat("0", 64)}, "kek-v1", wrapper); !errors.Is(err, ErrEnvelopeDigestMismatch) {
		t.Fatalf("digest mismatch err=%v", err)
	}
}

func TestEnvelopeRequiresNonZeroPolicyEpochAndLowercaseDigest(t *testing.T) {
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("test-key")}}
	meta := EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit"}
	if _, err := SealEnvelope(context.Background(), []byte("payload"), meta, "kek-v1", wrapper); !errors.Is(err, ErrInvalidEnvelopeMetadata) {
		t.Fatalf("zero policy epoch accepted: %v", err)
	}
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	meta.PolicyEpoch = 1
	meta.SHA256Digest = strings.ToUpper(hex.EncodeToString(digest[:]))
	if _, err := SealEnvelope(context.Background(), payload, meta, "kek-v1", wrapper); !errors.Is(err, ErrEnvelopeDigestMismatch) {
		t.Fatalf("uppercase digest accepted: %v", err)
	}
}

func TestRewrapChangesKeyVersionAndRetainsOldEnvelope(t *testing.T) {
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("old-key"), "kek-v2": []byte("new-key")}}
	meta := EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit", PolicyEpoch: 2}
	payload := []byte("rotation payload")
	old, err := SealEnvelope(context.Background(), payload, meta, "kek-v1", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := RewrapEnvelope(context.Background(), old, "kek-v2", wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KeyVersion != "kek-v2" || bytes.Equal(rotated.WrappedDEK, old.WrappedDEK) {
		t.Fatalf("unexpected rotation: old=%q new=%q", old.KeyVersion, rotated.KeyVersion)
	}
	if !bytes.Equal(rotated.Ciphertext, old.Ciphertext) || !bytes.Equal(rotated.Nonce, old.Nonce) {
		t.Fatal("rewrap must not change ciphertext or nonce")
	}
	if got, err := OpenEnvelope(context.Background(), old, wrapper); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("old envelope no longer opens: %q %v", got, err)
	}
	if got, err := OpenEnvelope(context.Background(), rotated, wrapper); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("rotated envelope does not open: %q %v", got, err)
	}
}

func TestEnvelopeKeyProviderFailuresAreClassified(t *testing.T) {
	wrapErr := errors.New("kms unavailable")
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("old-key")}, wrapErr: wrapErr}
	meta := EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit", PolicyEpoch: 1}
	if _, err := SealEnvelope(context.Background(), []byte("payload"), meta, "kek-v1", wrapper); !errors.Is(err, ErrEnvelopeKeyWrap) || !errors.Is(err, wrapErr) {
		t.Fatalf("wrap error=%v", err)
	}
	validWrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("old-key")}}
	envelope, err := SealEnvelope(context.Background(), []byte("payload"), meta, "kek-v1", validWrapper)
	if err != nil {
		t.Fatal(err)
	}
	unwrapErr := errors.New("kms denied")
	validWrapper.unwrapErr = unwrapErr
	if _, err := OpenEnvelope(context.Background(), envelope, validWrapper); !errors.Is(err, ErrEnvelopeKeyUnwrap) || !errors.Is(err, unwrapErr) {
		t.Fatalf("unwrap error=%v", err)
	}
}

func TestEnvelopeContextCancellationStopsProviderWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wrapper := testKeyWrapper{keys: map[string][]byte{"kek-v1": []byte("old-key")}}
	meta := EnvelopeMetadata{TenantID: "tenant", PluginID: "plugin", PluginVersion: "1.0.0", Target: "audit", PolicyEpoch: 1}
	if _, err := SealEnvelope(ctx, []byte("payload"), meta, "kek-v1", wrapper); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled seal err=%v", err)
	}
}
