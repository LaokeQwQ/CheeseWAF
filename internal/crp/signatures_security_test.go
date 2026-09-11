package crp

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignatureTimestampIsAuthenticatedAndFutureTimestampsRejected(t *testing.T) {
	m, private, now := signatureFixture(t)
	root := officialRoot(private)
	store, err := NewTrustStore([]TrustRoot{root})
	if err != nil {
		t.Fatal(err)
	}
	sigs := []Signature{
		signFor(t, m, private[0], "official-a", now),
		signFor(t, m, private[1], "official-b", now),
	}
	if _, err := store.VerifyManifest(m, sigs, VerificationOptions{Now: now}); err != nil {
		t.Fatalf("valid signatures rejected: %v", err)
	}
	sigs[0].SignedAt = now.Add(24 * time.Hour)
	if _, err := store.VerifyManifest(m, sigs, VerificationOptions{Now: now}); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered timestamp accepted: %v", err)
	}
	future := []Signature{
		signFor(t, m, private[0], "official-a", now.Add(time.Minute)),
		signFor(t, m, private[1], "official-b", now.Add(time.Minute)),
	}
	if _, err := store.VerifyManifest(m, future, VerificationOptions{Now: now}); !errors.Is(err, ErrSignature) {
		t.Fatalf("future signatures accepted: %v", err)
	}
}

func TestTrustRootRejectsWeakEnterprisePolicyAndDuplicatePublicKeys(t *testing.T) {
	_, private, _ := signatureFixture(t)
	weak := TrustRoot{
		ID: "enterprise-weak", Class: SignerEnterprise, NamespacePrefixes: []string{"enterprise/acme/"},
		Keys: []TrustKey{
			{ID: "a", PublicKey: private[0].Public().(ed25519.PublicKey)},
			{ID: "b", PublicKey: private[1].Public().(ed25519.PublicKey)},
			{ID: "c", PublicKey: private[2].Public().(ed25519.PublicKey)},
		},
		Policy: SignaturePolicy{Threshold: 1, Total: 1}, HighRiskPolicy: SignaturePolicy{Threshold: 1, Total: 1},
	}
	if _, err := NewTrustStore([]TrustRoot{weak}); !errors.Is(err, ErrTrustRoot) {
		t.Fatalf("weak enterprise policy accepted: %v", err)
	}
	duplicate := weak
	duplicate.Policy, duplicate.HighRiskPolicy = SignaturePolicy{}, SignaturePolicy{}
	duplicate.Keys[1].PublicKey = duplicate.Keys[0].PublicKey
	if _, err := NewTrustStore([]TrustRoot{duplicate}); !errors.Is(err, ErrTrustRoot) {
		t.Fatalf("duplicate public key accepted: %v", err)
	}
}

func TestTrustRootRejectsKeyLifetimeBeyondClassMaximum(t *testing.T) {
	_, private, _ := signatureFixture(t)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root := TrustRoot{
		ID: "community-root", Class: SignerCommunity, NamespacePrefixes: []string{"community/alice/"},
		Keys: []TrustKey{{ID: "alice", PublicKey: private[0].Public().(ed25519.PublicKey), NotBefore: start, NotAfter: start.Add(2 * 365 * 24 * time.Hour)}},
	}
	if _, err := NewTrustStore([]TrustRoot{root}); !errors.Is(err, ErrTrustRoot) {
		t.Fatalf("overlong key lifetime accepted: %v", err)
	}
}

func TestTrustRootRejectsClassNamespaceMismatch(t *testing.T) {
	_, private, _ := signatureFixture(t)
	cases := []TrustRoot{
		{ID: "official-enterprise", Class: SignerOfficial, NamespacePrefixes: []string{"enterprise/acme/"}, Keys: []TrustKey{{ID: "k", PublicKey: private[0].Public().(ed25519.PublicKey)}}},
		{ID: "enterprise-official", Class: SignerEnterprise, NamespacePrefixes: []string{"official/plugin"}, Keys: []TrustKey{{ID: "k", PublicKey: private[0].Public().(ed25519.PublicKey)}}},
		{ID: "community-enterprise", Class: SignerCommunity, NamespacePrefixes: []string{"enterprise/acme/"}, Keys: []TrustKey{{ID: "k", PublicKey: private[0].Public().(ed25519.PublicKey)}}},
	}
	for _, root := range cases {
		if _, err := NewTrustStore([]TrustRoot{root}); !errors.Is(err, ErrTrustRoot) {
			t.Errorf("namespace/class mismatch accepted for %s: %v", root.ID, err)
		}
	}
}

func TestTrustStoreCopiesKeyMaterial(t *testing.T) {
	_, private, _ := signatureFixture(t)
	public := private[0].Public().(ed25519.PublicKey)
	root := TrustRoot{ID: "community-root", Class: SignerCommunity, NamespacePrefixes: []string{"community/alice/"}, Keys: []TrustKey{{ID: "alice", PublicKey: public}}}
	store, err := NewTrustStore([]TrustRoot{root})
	if err != nil {
		t.Fatal(err)
	}
	want := root.Keys[0].PublicKey[0]
	root.Keys[0].PublicKey[0] ^= 0xff
	got, _ := store.Root("community-root")
	got.Keys[0].PublicKey[0] ^= 0xff
	again, _ := store.Root("community-root")
	if again.Keys[0].PublicKey[0] != want {
		t.Fatal("trust store key material was mutable through input or getter")
	}
}

func TestRevokeDoesNotMutatePreviousSnapshot(t *testing.T) {
	m, private, now := signatureFixture(t)
	m.Namespace, m.SourceRoot = "community/alice/rate-limit", "community-root"
	store, err := NewTrustStore([]TrustRoot{{ID: "community-root", Class: SignerCommunity, NamespacePrefixes: []string{"community/alice/"}, Keys: []TrustKey{{ID: "alice", PublicKey: private[0].Public().(ed25519.PublicKey)}}}})
	if err != nil {
		t.Fatal(err)
	}
	sig := signFor(t, m, private[0], "alice", now)
	revoked, err := store.Revoke("community-root", "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyManifest(m, []Signature{sig}, VerificationOptions{Now: now, AllowConfirmation: true}); err != nil {
		t.Fatalf("previous snapshot changed after revoke: %v", err)
	}
	if _, err := revoked.VerifyManifest(m, []Signature{sig}, VerificationOptions{Now: now, AllowConfirmation: true}); !errors.Is(err, ErrRevokedSigner) {
		t.Fatalf("revoked snapshot error=%v, want ErrRevokedSigner", err)
	}
}
