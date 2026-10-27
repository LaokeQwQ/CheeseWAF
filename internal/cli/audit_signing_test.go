package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func writeEd25519Fixture(t *testing.T, dir string) (string, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "audit.key")
	publicPath := filepath.Join(dir, "audit.pub")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath, "audit-key-1"
}

func TestLoadAuditSigningReadsKeyAndVerifiers(t *testing.T) {
	dir := t.TempDir()
	privatePath, publicPath, keyID := writeEd25519Fixture(t, dir)
	signer, verifiers, err := loadAuditSigning(config.AuditSigningConfig{
		Enabled:       true,
		SignerKeyID:   keyID,
		SignerKeyFile: privatePath,
		Verifiers:     []config.AuditVerifierConfig{{KeyID: keyID, PublicKeyFile: publicPath}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil || signer.KeyID() != keyID {
		t.Fatalf("signer=%v", signer)
	}
	signature, err := signer.Sign([]byte("checkpoint"))
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature len=%d err=%v", len(signature), err)
	}
	if len(verifiers[keyID]) != ed25519.PublicKeySize || !ed25519.Verify(verifiers[keyID], []byte("checkpoint"), signature) {
		t.Fatal("verifier key does not match the signing key")
	}
}

func TestLoadAuditSigningRejectsLoosePermissionsAndDuplicates(t *testing.T) {
	dir := t.TempDir()
	privatePath, publicPath, keyID := writeEd25519Fixture(t, dir)
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAuditSigning(config.AuditSigningConfig{Enabled: true, SignerKeyID: keyID, SignerKeyFile: privatePath}); err == nil {
		t.Fatal("world-readable signing key must be rejected")
	}
	if err := os.Chmod(privatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadAuditSigning(config.AuditSigningConfig{
		Enabled:       true,
		SignerKeyID:   keyID,
		SignerKeyFile: privatePath,
		Verifiers: []config.AuditVerifierConfig{
			{KeyID: "dup", PublicKeyFile: publicPath},
			{KeyID: "dup", PublicKeyFile: publicPath},
		},
	})
	if err == nil {
		t.Fatal("duplicate verifier key ids must be rejected")
	}
}

func TestLoadAuditSigningDisabledIsNoop(t *testing.T) {
	signer, verifiers, err := loadAuditSigning(config.AuditSigningConfig{})
	if err != nil || signer != nil || verifiers != nil {
		t.Fatalf("signer=%v verifiers=%v err=%v", signer, verifiers, err)
	}
}
