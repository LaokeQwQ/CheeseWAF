package envelope

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func testMetadata() Metadata {
	return Metadata{
		TenantID:      "tenant-a",
		PluginID:      "diag",
		PluginVersion: "1.2.3",
		Target:        "tenant-a/audit",
		PolicyEpoch:   7,
	}
}

func testLocalProvider(t *testing.T) *LocalProvider {
	t.Helper()
	p, err := NewLocalProvider("kek-v1", bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSealOpenUsesIndependentDEKAndAuthenticatesAAD(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	payload := []byte(`{"kind":"sanitized"}`)
	a, err := Seal(context.Background(), payload, testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(context.Background(), payload, testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || a.ID != a.EnvelopeID || a.ID == b.ID {
		t.Fatalf("envelope IDs are not independent: %#v %#v", a, b)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("each package must use an independent DEK and nonce")
	}
	encoded, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, payload) {
		t.Fatal("serialized envelope leaked plaintext")
	}
	opened, err := Open(context.Background(), a, p)
	if err != nil || !bytes.Equal(opened, payload) {
		t.Fatalf("open=%q err=%v", opened, err)
	}
	digest := sha256.Sum256(payload)
	if a.Metadata.SHA256Digest != hex.EncodeToString(digest[:]) {
		t.Fatalf("digest=%q", a.Metadata.SHA256Digest)
	}
	for name, mutate := range map[string]func(*Metadata){
		"tenant":  func(m *Metadata) { m.TenantID = "tenant-b" },
		"plugin":  func(m *Metadata) { m.PluginID = "other" },
		"version": func(m *Metadata) { m.PluginVersion = "9.9.9" },
		"target":  func(m *Metadata) { m.Target = "other-target" },
		"digest":  func(m *Metadata) { m.SHA256Digest = strings.Repeat("a", 64) },
		"epoch":   func(m *Metadata) { m.PolicyEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := a
			tampered.Metadata = a.Metadata
			mutate(&tampered.Metadata)
			if err := Verify(context.Background(), tampered, p); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("tamper err=%v", err)
			}
		})
	}
}

func TestAADLengthPrefixesPreventFieldConcatenationAmbiguity(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	first := testMetadata()
	first.TenantID, first.PluginID = "ab", "c"
	second := testMetadata()
	second.TenantID, second.PluginID = "a", "bc"
	a, err := Seal(context.Background(), []byte("same"), first, "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(context.Background(), []byte("same"), second, "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), Envelope{ID: a.ID, EnvelopeID: a.EnvelopeID, SchemaVersion: a.SchemaVersion, Algorithm: a.Algorithm, KeyVersion: a.KeyVersion, WrappedDEK: a.WrappedDEK, Nonce: a.Nonce, Ciphertext: a.Ciphertext, Metadata: b.Metadata}, p); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("ambiguous AAD accepted: %v", err)
	}
}

func TestStrictEnvelopeBoundaries(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	for name, meta := range map[string]Metadata{
		"tenant leading space":        func() Metadata { m := testMetadata(); m.TenantID = " tenant"; return m }(),
		"plugin invisible whitespace": func() Metadata { m := testMetadata(); m.PluginID = "plug\u200b"; return m }(),
		"target newline":              func() Metadata { m := testMetadata(); m.Target = "audit\npath"; return m }(),
		"zero epoch":                  func() Metadata { m := testMetadata(); m.PolicyEpoch = 0; return m }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Seal(context.Background(), []byte("payload"), meta, "kek-v1", p); !errors.Is(err, ErrInvalidMetadata) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	for name, mutate := range map[string]func(*Envelope){
		"version":              func(e *Envelope) { e.SchemaVersion = "diagnostic-envelope.v0" },
		"algorithm":            func(e *Envelope) { e.Algorithm = "AES-128-GCM" },
		"nonce short":          func(e *Envelope) { e.Nonce = e.Nonce[:len(e.Nonce)-1] },
		"wrapped key empty":    func(e *Envelope) { e.WrappedDEK = nil },
		"ciphertext tag short": func(e *Envelope) { e.Ciphertext = e.Ciphertext[:15] },
	} {
		t.Run(name, func(t *testing.T) {
			base, err := Seal(context.Background(), []byte("payload"), testMetadata(), "kek-v1", p)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&base)
			if err := Verify(context.Background(), base, p); err == nil {
				t.Fatal("malformed envelope accepted")
			}
		})
	}
}

func TestOpenOnceRejectsReplayAtomically(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	e, err := Seal(context.Background(), []byte("one-shot"), testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	guard := NewMemoryReplayGuard(16)
	if got, err := OpenOnce(context.Background(), e, p, guard); err != nil || string(got) != "one-shot" {
		t.Fatalf("first open=%q err=%v", got, err)
	}
	if _, err := OpenOnce(context.Background(), e, p, guard); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay err=%v", err)
	}
	tampered := e
	tampered.Ciphertext = append([]byte(nil), e.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	if _, err := OpenOnce(context.Background(), tampered, p, guard); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered replay err=%v", err)
	}
}

func TestRewrapRotatesKEKWithoutReencryptingPackage(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	if err := p.Rotate("kek-v2", bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	plain := []byte("rotation payload")
	original, err := Seal(context.Background(), plain, testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := Rewrap(context.Background(), original, "kek-v2", p)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KeyVersion != "kek-v2" || bytes.Equal(rotated.WrappedDEK, original.WrappedDEK) {
		t.Fatalf("rotation did not change wrapped key: %#v", rotated)
	}
	if !bytes.Equal(rotated.Ciphertext, original.Ciphertext) || !bytes.Equal(rotated.Nonce, original.Nonce) || rotated.ID != original.ID {
		t.Fatal("rewrap must preserve package ciphertext, nonce, and identity")
	}
	if got, err := Open(context.Background(), rotated, p); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("rotated open=%q err=%v", got, err)
	}
}

func TestKEKVersionIsImmutableAcrossRotation(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()

	if err := p.Rotate("kek-v1", bytes.Repeat([]byte{0x42}, DEKSize)); !errors.Is(err, ErrKeyVersionExists) {
		t.Fatalf("key version replacement err=%v", err)
	}

	original, err := Seal(context.Background(), []byte("rotation"), testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rewrap(context.Background(), original, "kek-v1", p); !errors.Is(err, ErrKeyRotationNoop) {
		t.Fatalf("same-version rewrap err=%v", err)
	}
	if got, err := Open(context.Background(), original, p); err != nil || string(got) != "rotation" {
		t.Fatalf("original envelope after rejected rotation=%q err=%v", got, err)
	}
}

func TestLocalProviderIsExplicitAndErasesOnClose(t *testing.T) {
	if _, err := Seal(context.Background(), []byte("payload"), testMetadata(), "kek-v1", nil); !errors.Is(err, ErrKeyWrap) {
		t.Fatalf("nil provider silently bypassed: %v", err)
	}
	p := testLocalProvider(t)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(context.Background(), []byte("payload"), testMetadata(), "kek-v1", p); !errors.Is(err, ErrKeyWrap) {
		t.Fatalf("closed local provider still usable: %v", err)
	}
}

type nilKeyProvider struct{}

func (*nilKeyProvider) Wrap(context.Context, string, []byte) ([]byte, error)   { return nil, nil }
func (*nilKeyProvider) Unwrap(context.Context, string, []byte) ([]byte, error) { return nil, nil }

func TestTypedNilProviderFailsClosedWithoutPanic(t *testing.T) {
	var provider *nilKeyProvider
	if _, err := Seal(context.Background(), []byte("payload"), testMetadata(), "kek-v1", provider); !errors.Is(err, ErrKeyWrap) {
		t.Fatalf("typed nil provider err=%v", err)
	}
	if err := Verify(context.Background(), Envelope{}, provider); !errors.Is(err, ErrKeyUnwrap) {
		t.Fatalf("typed nil verify err=%v", err)
	}
}

type availabilityProvider struct {
	available bool
	wrapped   []byte
}

func (p availabilityProvider) Available(context.Context) bool { return p.available }
func (p availabilityProvider) Wrap(context.Context, string, []byte) ([]byte, error) {
	return append([]byte(nil), p.wrapped...), nil
}
func (p availabilityProvider) Unwrap(context.Context, string, []byte) ([]byte, error) {
	return bytes.Repeat([]byte{1}, DEKSize), nil
}

func TestSelectProviderPrefersExternalAndRequiresExplicitOfflineApproval(t *testing.T) {
	local := testLocalProvider(t)
	defer local.Close()
	external := &availabilityProvider{available: true, wrapped: []byte{1}}
	selected, err := SelectProvider(external, local, false)
	if err != nil || selected != external {
		t.Fatalf("external selection=%#v err=%v", selected, err)
	}
	if _, err := SelectProvider(availabilityProvider{available: false}, local, false); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("implicit local fallback accepted: %v", err)
	}
	selected, err = SelectProvider(&availabilityProvider{available: false}, local, true)
	if err != nil || selected != local {
		t.Fatalf("approved local selection=%#v err=%v", selected, err)
	}
}

func TestReplayGuardConcurrentFirstUse(t *testing.T) {
	guard := NewMemoryReplayGuard(4)
	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := guard.CheckAndMark(context.Background(), "same-id"); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted=%d, want exactly one", accepted)
	}
}

func TestReplayGuardReservationReleaseAllowsRetry(t *testing.T) {
	guard := NewMemoryReplayGuard(1)
	const id = "0123456789abcdef0123456789abcdef"
	if err := guard.Reserve(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := guard.Reserve(context.Background(), id); !errors.Is(err, ErrReplay) {
		t.Fatalf("concurrent reservation err=%v", err)
	}
	if err := guard.Release(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := guard.Reserve(context.Background(), id); err != nil {
		t.Fatalf("retry reservation err=%v", err)
	}
	if err := guard.Commit(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := guard.Reserve(context.Background(), id); !errors.Is(err, ErrReplay) {
		t.Fatalf("committed reservation err=%v", err)
	}
}

func TestDecodeStrictlyRejectsUnknownAndTrailingJSON(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	e, err := Seal(context.Background(), []byte("decode"), testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := Decode(raw); err != nil || decoded.ID != e.ID {
		t.Fatalf("decode=%#v err=%v", decoded, err)
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(",\"unknown\":true}")...)
	if _, err := Decode(unknown); err == nil {
		t.Fatal("unknown envelope field accepted")
	}
	trailing := append(append([]byte(nil), raw...), []byte("{}")...)
	if _, err := Decode(trailing); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestEnvelopeIdentityMustBeCanonicalHex(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	e, err := Seal(context.Background(), []byte("id"), testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"short", strings.ToUpper(e.ID), strings.Repeat("g", len(e.ID))} {
		tampered := e
		tampered.ID = id
		tampered.EnvelopeID = id
		if err := Validate(tampered); err == nil {
			t.Fatalf("non-canonical id accepted: %q", id)
		}
	}
	zeroNonce := e
	zeroNonce.Nonce = make([]byte, NonceSize)
	if err := Validate(zeroNonce); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("all-zero nonce accepted: %v", err)
	}
}

func TestReplayGuardFailsClosedWhenFull(t *testing.T) {
	guard := NewMemoryReplayGuard(1)
	if err := guard.CheckAndMark(context.Background(), strings.Repeat("a", EnvelopeIDSize*2)); err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckAndMark(context.Background(), strings.Repeat("b", EnvelopeIDSize*2)); !errors.Is(err, ErrReplayGuardFull) {
		t.Fatalf("full guard err=%v", err)
	}
	if err := guard.CheckAndMark(context.Background(), strings.Repeat("a", EnvelopeIDSize*2)); !errors.Is(err, ErrReplay) {
		t.Fatalf("existing id after full err=%v", err)
	}
}

func TestRetiredKeyVersionCannotOpenOldEnvelopeAfterRewrap(t *testing.T) {
	p := testLocalProvider(t)
	defer p.Close()
	if err := p.Rotate("kek-v2", bytes.Repeat([]byte{0x42}, DEKSize)); err != nil {
		t.Fatal(err)
	}
	e, err := Seal(context.Background(), []byte("retire"), testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Rewrap(context.Background(), e, "kek-v2", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Retire("kek-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), e, p); !errors.Is(err, ErrProviderKeyNotFound) {
		t.Fatalf("retired key accepted: %v", err)
	}
	if _, err := Open(context.Background(), r, p); err != nil {
		t.Fatalf("rotated envelope failed after old key retirement: %v", err)
	}
}

type freshProvider struct {
	wrapInput  []byte
	storedDEK  []byte
	lastReturn []byte
}

func (p *freshProvider) Wrap(_ context.Context, _ string, dek []byte) ([]byte, error) {
	p.wrapInput = dek
	p.storedDEK = append([]byte(nil), dek...)
	return []byte{1}, nil
}

func (p *freshProvider) Unwrap(_ context.Context, _ string, _ []byte) ([]byte, error) {
	p.lastReturn = append([]byte(nil), p.storedDEK...)
	return p.lastReturn, nil
}

func TestKeyBuffersAreErasedAtApplicationBoundary(t *testing.T) {
	p := &freshProvider{}
	e, err := Seal(context.Background(), []byte("ownership"), testMetadata(), "kek-v1", p)
	if err != nil {
		t.Fatal(err)
	}
	if !allZero(p.wrapInput) {
		t.Fatal("DEK buffer passed to provider was not erased after wrapping")
	}
	if got, err := Open(context.Background(), e, p); err != nil || string(got) != "ownership" {
		t.Fatalf("first open=%q err=%v", got, err)
	}
	if !allZero(p.lastReturn) {
		t.Fatal("unwrapped DEK buffer was not erased at application boundary")
	}
	if got, err := Open(context.Background(), e, p); err != nil || string(got) != "ownership" {
		t.Fatalf("second open=%q err=%v", got, err)
	}
}

func TestLocalProviderCloseErasesKEK(t *testing.T) {
	p := testLocalProvider(t)
	key := p.keys["kek-v1"]
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !allZero(key) {
		t.Fatal("local provider KEK was not erased on close")
	}
}
