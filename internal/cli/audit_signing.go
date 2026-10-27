package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

var auditKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// loadAuditSigning loads the Ed25519 signing key and trusted verifier keys for
// the tamper-evident audit stream. Every path must be absolute and every key
// file must be private to the process owner; an unreadable or world-readable key
// aborts startup instead of degrading to unsigned checkpoints.
func loadAuditSigning(cfg config.AuditSigningConfig) (audit.Signer, map[string]ed25519.PublicKey, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}
	if !auditKeyIDPattern.MatchString(cfg.SignerKeyID) {
		return nil, nil, fmt.Errorf("audit signing: invalid signer_key_id %q", cfg.SignerKeyID)
	}
	privateKey, err := readEd25519PrivateKey(cfg.SignerKeyFile)
	if err != nil {
		return nil, nil, err
	}
	verifiers := make(map[string]ed25519.PublicKey, len(cfg.Verifiers))
	for _, verifier := range cfg.Verifiers {
		if !auditKeyIDPattern.MatchString(verifier.KeyID) {
			return nil, nil, fmt.Errorf("audit signing: invalid verifier key_id %q", verifier.KeyID)
		}
		if _, exists := verifiers[verifier.KeyID]; exists {
			return nil, nil, fmt.Errorf("audit signing: duplicate verifier key_id %q", verifier.KeyID)
		}
		publicKey, readErr := readEd25519PublicKey(verifier.PublicKeyFile)
		if readErr != nil {
			return nil, nil, readErr
		}
		verifiers[verifier.KeyID] = publicKey
	}
	return audit.Ed25519Signer{ID: cfg.SignerKeyID, PrivateKey: privateKey}, verifiers, nil
}

func readEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readPrivateKeyFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("audit signing: %s must contain a PEM PKCS#8 key or a raw %d-byte key", path, ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("audit signing: %s must contain a PKCS#8 PRIVATE KEY block, got %q", path, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit signing: parse %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("audit signing: %s does not contain an Ed25519 private key", path)
	}
	return key, nil
}

func readEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := readPublicKeyFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("audit signing: %s must contain a PEM PUBLIC KEY block", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("audit signing: parse %s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("audit signing: %s does not contain an Ed25519 public key", path)
	}
	return key, nil
}

func readPrivateKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("audit signing: key path %q must be absolute", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("audit signing: stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("audit signing: %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("audit signing: %s must not be accessible by group or others (mode %04o)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit signing: read %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("audit signing: %s is empty", path)
	}
	return raw, nil
}

func readPublicKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("audit signing: verifier path %q must be absolute", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit signing: read %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("audit signing: %s is empty", path)
	}
	return raw, nil
}
