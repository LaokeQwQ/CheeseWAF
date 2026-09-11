package crp

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func signatureFixture(t *testing.T) (Manifest, []ed25519.PrivateKey, time.Time) {
	t.Helper()
	data := []byte("signed-crp")
	m := testManifest(data)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	keys := make([]ed25519.PrivateKey, 5)
	for i := range keys {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = private
	}
	return m, keys, now
}

func officialRoot(keys []ed25519.PrivateKey) TrustRoot {
	registered := make([]TrustKey, len(keys))
	for i, key := range keys {
		registered[i] = TrustKey{ID: "official-" + string(rune('a'+i)), PublicKey: key.Public().(ed25519.PublicKey), Class: SignerOfficial}
	}
	return TrustRoot{ID: "vendor-root-v1", Class: SignerOfficial, NamespacePrefixes: []string{"official/"}, Keys: registered}
}

func signFor(t *testing.T, m Manifest, key ed25519.PrivateKey, id string, at time.Time) Signature {
	t.Helper()
	sig, err := SignManifestWithKeyID(m, id, key, at)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestOfficialThresholdAndHighRiskPolicy(t *testing.T) {
	m, private, now := signatureFixture(t)
	store, err := NewTrustStore([]TrustRoot{officialRoot(private[:3])})
	if err != nil {
		t.Fatal(err)
	}
	valid := []Signature{signFor(t, m, private[0], "official-a", now), signFor(t, m, private[1], "official-b", now)}
	report, err := store.VerifyManifest(m, valid, VerificationOptions{Now: now})
	if err != nil || report.Status != VerificationTrusted || report.ValidSignatures != 2 {
		t.Fatalf("normal threshold report=%+v err=%v", report, err)
	}
	highReport, err := store.VerifyManifest(m, valid, VerificationOptions{Now: now, HighRisk: true})
	if !errors.Is(err, ErrThresholdNotMet) {
		t.Fatalf("high-risk quorum report=%+v err=%v, want ErrThresholdNotMet", highReport, err)
	}
	rotated, err := store.Rotate("vendor-root-v1", []TrustKey{
		{ID: "official-d", PublicKey: private[3].Public().(ed25519.PublicKey), Class: SignerOfficial},
		{ID: "official-e", PublicKey: private[4].Public().(ed25519.PublicKey), Class: SignerOfficial},
	})
	if err != nil {
		t.Fatal(err)
	}
	high := append(valid, signFor(t, m, private[2], "official-c", now))
	high = append(high, signFor(t, m, private[3], "official-d", now), signFor(t, m, private[4], "official-e", now))
	report, err = rotated.VerifyManifest(m, high, VerificationOptions{Now: now, HighRisk: true})
	if err != nil || report.Status != VerificationTrusted || report.ValidSignatures != 5 {
		t.Fatalf("rotated high-risk report=%+v err=%v", report, err)
	}
}

func TestEnterpriseDefaultsToPlatformThresholds(t *testing.T) {
	_, private, _ := signatureFixture(t)
	store, err := NewTrustStore([]TrustRoot{{
		ID: "enterprise-default", Class: SignerEnterprise,
		NamespacePrefixes: []string{"enterprise/acme/"},
		Keys: []TrustKey{
			{ID: "k1", PublicKey: private[0].Public().(ed25519.PublicKey)},
			{ID: "k2", PublicKey: private[1].Public().(ed25519.PublicKey)},
			{ID: "k3", PublicKey: private[2].Public().(ed25519.PublicKey)},
			{ID: "k4", PublicKey: private[3].Public().(ed25519.PublicKey)},
			{ID: "k5", PublicKey: private[4].Public().(ed25519.PublicKey)},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	root, ok := store.Root("enterprise-default")
	if !ok {
		t.Fatal("enterprise root missing")
	}
	if root.Policy != (SignaturePolicy{Threshold: 2, Total: 3}) || root.HighRiskPolicy != (SignaturePolicy{Threshold: 3, Total: 5}) {
		t.Fatalf("enterprise policies=%+v/%+v, want 2-of-3/3-of-5", root.Policy, root.HighRiskPolicy)
	}
}

func TestUnknownUntrustedAndRevokedSigners(t *testing.T) {
	m, private, now := signatureFixture(t)
	store, err := NewTrustStore([]TrustRoot{{ID: "community-root", Class: SignerUntrusted, NamespacePrefixes: []string{"community/alice/"}, Keys: []TrustKey{{ID: "alice", PublicKey: private[0].Public().(ed25519.PublicKey), Class: SignerUntrusted}}, MaxValidity: 365 * 24 * time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	m.Namespace, m.SourceRoot = "community/alice/rate-limit", "community-root"
	sig := signFor(t, m, private[0], "alice", now)
	report, err := store.VerifyManifest(m, []Signature{sig}, VerificationOptions{Now: now})
	if report.Status != VerificationNeedsConfirmation || !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("untrusted report=%+v err=%v", report, err)
	}
	report, err = store.VerifyManifest(m, []Signature{sig}, VerificationOptions{Now: now, AllowConfirmation: true})
	if err != nil || report.Status != VerificationNeedsConfirmation {
		t.Fatalf("confirmed untrusted report=%+v err=%v", report, err)
	}
	unknown := sig
	unknown.KeyID = "missing"
	if _, err := store.VerifyManifest(m, []Signature{unknown}, VerificationOptions{Now: now, AllowConfirmation: true}); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer err=%v", err)
	}
	revoked, err := store.Revoke("community-root", "alice", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revoked.VerifyManifest(m, []Signature{sig}, VerificationOptions{Now: now, AllowConfirmation: true}); !errors.Is(err, ErrRevokedSigner) {
		t.Fatalf("revoked signer err=%v, want ErrRevokedSigner", err)
	}
}

func TestSignerValidityWindowAndRotationImmutability(t *testing.T) {
	m, private, now := signatureFixture(t)
	before, after := now.Add(-time.Hour), now.Add(time.Hour)
	root := officialRoot(private)
	root.ID, root.Class, root.NamespacePrefixes = "enterprise-acme", SignerEnterprise, []string{"enterprise/acme/"}
	for i := range root.Keys {
		root.Keys[i].Class = SignerEnterprise
		root.Keys[i].NotBefore, root.Keys[i].NotAfter = before, after
	}
	store, err := NewTrustStore([]TrustRoot{root})
	if err != nil {
		t.Fatal(err)
	}
	m.Namespace, m.SourceRoot = "enterprise/acme/rate-limit", "enterprise-acme"
	valid := signFor(t, m, private[0], "official-a", now)
	valid2 := signFor(t, m, private[1], "official-b", now)
	if _, err := store.VerifyManifest(m, []Signature{valid, valid2}, VerificationOptions{Now: now}); err != nil {
		t.Fatalf("valid enterprise signature rejected: %v", err)
	}
	late := signFor(t, m, private[0], "official-a", before.Add(-time.Second))
	if _, err := store.VerifyManifest(m, []Signature{late}, VerificationOptions{Now: now}); !errors.Is(err, ErrExpiredSigner) {
		t.Fatalf("expired signature err=%v", err)
	}
	_, rotationKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := store.Rotate("enterprise-acme", []TrustKey{{ID: "replacement", PublicKey: rotationKey.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Root("enterprise-acme"); !ok {
		t.Fatal("original store lost root")
	}
	if _, ok := rotated.Root("enterprise-acme"); !ok {
		t.Fatal("rotated store missing root")
	}
}

func TestDefaultRootValidityPolicies(t *testing.T) {
	m, private, now := signatureFixture(t)
	classes := []struct {
		class SignerClass
		max   time.Duration
		ns    string
	}{
		{SignerCommunity, 365 * 24 * time.Hour, "community/alice/"},
		{SignerPersonal, 365 * 24 * time.Hour, "personal/alice/"},
		{SignerTest, 30 * 24 * time.Hour, "test/nightly/"},
		{SignerDevelopment, 7 * 24 * time.Hour, "development/local/"},
	}
	for _, tc := range classes {
		t.Run(string(tc.class), func(t *testing.T) {
			store, err := NewTrustStore([]TrustRoot{{
				ID: "root-" + string(tc.class), Class: tc.class,
				NamespacePrefixes: []string{tc.ns},
				Keys:              []TrustKey{{ID: "k1", PublicKey: private[0].Public().(ed25519.PublicKey)}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			root, ok := store.Root("root-" + string(tc.class))
			if !ok || root.MaxValidity != tc.max {
				t.Fatalf("max validity=%s, want %s", root.MaxValidity, tc.max)
			}
			m.Namespace, m.SourceRoot = tc.ns+"rate-limit", root.ID
			valid := signFor(t, m, private[0], "k1", now)
			report, err := store.VerifyManifest(m, []Signature{valid}, VerificationOptions{Now: now})
			if !errors.Is(err, ErrConfirmationRequired) || report.Status != VerificationNeedsConfirmation {
				t.Fatalf("default untrusted signature report=%+v err=%v", report, err)
			}
			report, err = store.VerifyManifest(m, []Signature{valid}, VerificationOptions{Now: now, AllowConfirmation: true})
			if err != nil || report.Status != VerificationNeedsConfirmation {
				t.Fatalf("confirmed signature report=%+v err=%v", report, err)
			}
			old := signFor(t, m, private[0], "k1", now.Add(-tc.max).Add(-time.Second))
			if _, err := store.VerifyManifest(m, []Signature{old}, VerificationOptions{Now: now}); !errors.Is(err, ErrThresholdNotMet) {
				t.Fatalf("expired signature error=%v, want threshold failure", err)
			}
		})
	}
}
