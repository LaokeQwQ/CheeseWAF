package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/recovery"
)

type source struct {
	key         []byte
	unsupported bool
}

type allowCredentialAuthorizer struct{}

func (allowCredentialAuthorizer) Authorize(context.Context, Access) error { return nil }

type allowProofVerifier struct{}

func (allowProofVerifier) Verify(context.Context, Proof) error { return nil }

type credentialAudit struct{}

func (credentialAudit) Append(context.Context, Event) error { return nil }

func (s source) Available(context.Context) bool { return !s.unsupported && len(s.key) == 32 }
func (s source) Load(context.Context) ([]byte, error) {
	if s.unsupported {
		return nil, ErrUnsupported
	}
	if len(s.key) != 32 {
		return nil, errors.New("bad source")
	}
	return append([]byte(nil), s.key...), nil
}

func TestEncryptedKeyringUsesInjectedSourceAndNeverPersistsKEKPlaintext(t *testing.T) {
	master := bytes.Repeat([]byte{0x71}, 32)
	kr, err := NewEncryptedKeyring(source{key: master})
	if err != nil {
		t.Fatal(err)
	}
	ref := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	kek := bytes.Repeat([]byte{0x41}, 32)
	if err := kr.Put(context.Background(), ref, kek); err != nil {
		t.Fatal(err)
	}
	blob, err := kr.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, kek) || bytes.Contains(blob, master) {
		t.Fatal("keyring persisted plaintext key material")
	}
	opened, err := OpenEncryptedKeyring(context.Background(), source{key: master}, blob)
	if err != nil {
		t.Fatal(err)
	}
	got, err := opened.Get(context.Background(), ref)
	if err != nil || !bytes.Equal(got, kek) {
		t.Fatalf("get=%x err=%v", got, err)
	}
	for i := range got {
		got[i] = 0
	}
	for i := range kek {
		kek[i] = 0
	}
}

func TestKeyringBackendBindsTenantKeyVersionAndRejectsRevokedOrUnsupported(t *testing.T) {
	master := bytes.Repeat([]byte{0x72}, 32)
	kr, err := NewEncryptedKeyring(source{key: master})
	if err != nil {
		t.Fatal(err)
	}
	ref := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	if err := kr.Put(context.Background(), ref, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	b := NewKeyringBackend(kr)
	plain := make([]byte, DEKSize)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	wrapped, err := b.Wrap(context.Background(), ref, plain)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := b.Unwrap(context.Background(), ref, wrapped)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("open err=%v", err)
	}
	bad := ref
	bad.TenantID = "tenant-b"
	if _, err := b.Unwrap(context.Background(), bad, wrapped); !errors.Is(err, ErrBinding) {
		t.Fatalf("tenant mismatch=%v", err)
	}
	if err := kr.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Unwrap(context.Background(), ref, wrapped); !errors.Is(err, ErrVersion) {
		t.Fatalf("revoked version=%v", err)
	}
	unsupported := NewKeyringBackend(mustKeyring(t, source{unsupported: true}))
	if unsupported.Available(context.Background()) {
		t.Fatal("unsupported source reported available")
	}
	if _, err := unsupported.Wrap(context.Background(), ref, plain); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported=%v", err)
	}
}

func TestKeyringRotationKeepsOldVersionDecryptableUntilRevoked(t *testing.T) {
	kr := mustKeyring(t, source{key: bytes.Repeat([]byte{0x73}, 32)})
	old := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	newRef := old
	newRef.Version = "v2"
	if err := kr.Put(context.Background(), old, bytes.Repeat([]byte{0x41}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := kr.Rotate(context.Background(), newRef, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Get(context.Background(), old); err != nil {
		t.Fatalf("old version unavailable before revoke: %v", err)
	}
	if _, err := kr.Get(context.Background(), newRef); err != nil {
		t.Fatalf("new version unavailable: %v", err)
	}
	if err := kr.Revoke(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Get(context.Background(), old); !errors.Is(err, ErrVersion) {
		t.Fatalf("old version after revoke=%v", err)
	}
}

func TestKeyringExportAuthenticatesRevocationMetadata(t *testing.T) {
	kr := mustKeyring(t, source{key: bytes.Repeat([]byte{0x75}, 32)})
	ref := KeyRef{TenantID: "tenant-a", KeyID: "key-a", Version: "v1"}
	if err := kr.Put(context.Background(), ref, bytes.Repeat([]byte{0x41}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := kr.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	blob, err := kr.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var doc sealedKeyringDocument
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Ciphertext[0] ^= 1
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEncryptedKeyring(context.Background(), source{key: bytes.Repeat([]byte{0x75}, 32)}, tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("revocation metadata tampered: %v", err)
	}
}

func TestRecoveryCredentialIsUniqueTwoOfThreeAndOneShot(t *testing.T) {
	kr := mustKeyring(t, source{key: bytes.Repeat([]byte{0x74}, 32)})
	m, err := NewCredentialManager([]string{"admin-a", "admin-b", "admin-c"}, kr,
		WithCredentialAuthorizer(allowCredentialAuthorizer{}), WithCredentialAudit(credentialAudit{}), WithProofVerifier(allowProofVerifier{}))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.Issue(context.Background(), IssueRequest{Actor: "admin-a", Scope: "cluster", Risk: RiskHigh})
	if err != nil {
		t.Fatal(err)
	}
	if issued.ID == "" || issued.Secret == "" {
		t.Fatal("missing credential")
	}
	if _, err := m.Issue(context.Background(), IssueRequest{Actor: "admin-a", Scope: "cluster", Risk: RiskHigh}); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(context.Background(), issued.ID, "admin-a", "c1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RecoverWithCredential(context.Background(), issued.ID, issued.Secret, "admin-a", "c2"); !errors.Is(err, ErrThreshold) {
		t.Fatalf("duplicate admin=%v", err)
	}
	secret, err := m.RecoverWithCredential(context.Background(), issued.ID, issued.Secret, "admin-b", "c3")
	if err != nil || secret != issued.Secret {
		t.Fatalf("recover secret=%q err=%v", secret, err)
	}
	if _, err := m.RecoverWithCredential(context.Background(), issued.ID, issued.Secret, "admin-c", "c4"); !errors.Is(err, ErrRecoveryConsumed) {
		t.Fatalf("replay=%v", err)
	}
}

func mustKeyring(t *testing.T, s RootKeySource) *EncryptedKeyring {
	t.Helper()
	kr, err := NewEncryptedKeyring(s)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

var _ = recovery.SecretSize
