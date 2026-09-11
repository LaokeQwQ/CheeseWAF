// Package diagnostics contains the legacy compatibility envelope API and the
// fixed diagnostic broker contract. New encryption integrations must use the
// canonical internal/diagnostics/envelope subpackage; the two wire formats are
// intentionally not interchangeable.
package diagnostics

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	EnvelopeSchemaVersion = "diagnostic-envelope.v1"
	EnvelopeAlgorithm     = "AES-256-GCM"
	dekSize               = 32
)

var (
	ErrInvalidEnvelope         = errors.New("invalid diagnostic envelope")
	ErrInvalidEnvelopeMetadata = errors.New("invalid diagnostic envelope metadata")
	ErrUnsupportedEnvelope     = errors.New("unsupported diagnostic envelope")
	ErrEnvelopeDigestMismatch  = errors.New("diagnostic envelope digest mismatch")
	ErrEnvelopeKeyWrap         = errors.New("diagnostic envelope key wrapping failed")
	ErrEnvelopeKeyUnwrap       = errors.New("diagnostic envelope key unwrapping failed")
	ErrEnvelopeAuthentication  = errors.New("diagnostic envelope authentication failed")
)

// KeyWrapper is retained for legacy callers. It is not compatible with the
// canonical internal/diagnostics/envelope.KeyProvider wire contract.
type KeyWrapper interface {
	Wrap(ctx context.Context, keyVersion string, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, keyVersion string, wrappedDEK []byte) ([]byte, error)
}

// EnvelopeMetadata is authenticated as AAD. SHA256Digest is the identity of
// the plaintext diagnostic package and is always recomputed by SealEnvelope.
type EnvelopeMetadata struct {
	TenantID      string `json:"tenant_id"`
	PluginID      string `json:"plugin_id"`
	PluginVersion string `json:"plugin_version"`
	Target        string `json:"target"`
	SHA256Digest  string `json:"sha256"`
	PolicyEpoch   uint64 `json:"policy_epoch"`
}

// CiphertextEnvelope is the legacy envelope shape. New code must use the
// canonical internal/diagnostics/envelope.Envelope type; do not convert by
// assigning fields with the same names.
type CiphertextEnvelope struct {
	SchemaVersion string           `json:"schema_version"`
	Algorithm     string           `json:"algorithm"`
	KeyVersion    string           `json:"key_version"`
	WrappedDEK    []byte           `json:"wrapped_dek"`
	Nonce         []byte           `json:"nonce"`
	Ciphertext    []byte           `json:"ciphertext"`
	Metadata      EnvelopeMetadata `json:"metadata"`
}

// SealEnvelope encrypts one package using the legacy envelope format. New code
// should call internal/diagnostics/envelope.Seal instead.
func SealEnvelope(ctx context.Context, plaintext []byte, metadata EnvelopeMetadata, keyVersion string, wrapper KeyWrapper) (CiphertextEnvelope, error) {
	if err := contextErr(ctx); err != nil {
		return CiphertextEnvelope{}, err
	}
	if wrapper == nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: nil key wrapper", ErrEnvelopeKeyWrap)
	}
	if err := validateMetadataFields(metadata); err != nil {
		return CiphertextEnvelope{}, err
	}
	if metadata.PolicyEpoch == 0 {
		return CiphertextEnvelope{}, fmt.Errorf("%w: policy epoch must be non-zero", ErrInvalidEnvelopeMetadata)
	}
	keyVersion = strings.TrimSpace(keyVersion)
	if keyVersion == "" {
		return CiphertextEnvelope{}, fmt.Errorf("%w: empty key version", ErrEnvelopeKeyWrap)
	}
	digest := sha256.Sum256(plaintext)
	digestHex := hex.EncodeToString(digest[:])
	if metadata.SHA256Digest != "" && metadata.SHA256Digest != digestHex {
		return CiphertextEnvelope{}, ErrEnvelopeDigestMismatch
	}
	metadata.SHA256Digest = digestHex
	dek := make([]byte, dekSize)
	defer zeroBytes(dek)
	if _, err := rand.Read(dek); err != nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: generate DEK: %v", ErrEnvelopeKeyWrap, err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: initialize cipher: %v", ErrInvalidEnvelope, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: initialize AEAD: %v", ErrInvalidEnvelope, err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: generate nonce: %v", ErrInvalidEnvelope, err)
	}
	aad := envelopeAAD(metadata)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	wrapped, err := wrapper.Wrap(ctx, keyVersion, append([]byte(nil), dek...))
	if err != nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: %w", ErrEnvelopeKeyWrap, err)
	}
	if len(wrapped) == 0 {
		return CiphertextEnvelope{}, fmt.Errorf("%w: provider returned empty wrapped DEK", ErrEnvelopeKeyWrap)
	}
	return CiphertextEnvelope{
		SchemaVersion: EnvelopeSchemaVersion, Algorithm: EnvelopeAlgorithm, KeyVersion: keyVersion,
		WrappedDEK: append([]byte(nil), wrapped...), Nonce: append([]byte(nil), nonce...),
		Ciphertext: append([]byte(nil), ciphertext...), Metadata: metadata,
	}, nil
}

// OpenEnvelope verifies and decrypts a legacy envelope. It cannot open a
// canonical internal/diagnostics/envelope.Envelope.
func OpenEnvelope(ctx context.Context, envelope CiphertextEnvelope, wrapper KeyWrapper) ([]byte, error) {
	dek, err := unwrapAndValidate(ctx, envelope, wrapper)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	return openWithDEK(envelope, dek)
}

func openWithDEK(envelope CiphertextEnvelope, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DEK", ErrEnvelopeAuthentication)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize AEAD: %v", ErrEnvelopeAuthentication, err)
	}
	if len(envelope.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: invalid nonce", ErrInvalidEnvelope)
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, envelopeAAD(envelope.Metadata))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelopeAuthentication, err)
	}
	digest := sha256.Sum256(plaintext)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), envelope.Metadata.SHA256Digest) {
		zeroBytes(plaintext)
		return nil, ErrEnvelopeDigestMismatch
	}
	return plaintext, nil
}

// VerifyEnvelope performs authentication and digest verification without
// returning package bytes.
func VerifyEnvelope(ctx context.Context, envelope CiphertextEnvelope, wrapper KeyWrapper) error {
	plaintext, err := OpenEnvelope(ctx, envelope, wrapper)
	if plaintext != nil {
		zeroBytes(plaintext)
	}
	return err
}

// RewrapEnvelope rotates only the wrapped DEK in the legacy format. It cannot
// rewrap a canonical internal/diagnostics/envelope.Envelope.
func RewrapEnvelope(ctx context.Context, envelope CiphertextEnvelope, newKeyVersion string, wrapper KeyWrapper) (CiphertextEnvelope, error) {
	if err := contextErr(ctx); err != nil {
		return CiphertextEnvelope{}, err
	}
	newKeyVersion = strings.TrimSpace(newKeyVersion)
	if newKeyVersion == "" {
		return CiphertextEnvelope{}, fmt.Errorf("%w: empty key version", ErrEnvelopeKeyWrap)
	}
	oldDEK, err := unwrapAndValidate(ctx, envelope, wrapper)
	if err != nil {
		return CiphertextEnvelope{}, err
	}
	defer zeroBytes(oldDEK)
	plaintext, err := openWithDEK(envelope, oldDEK)
	if plaintext != nil {
		zeroBytes(plaintext)
	}
	if err != nil {
		return CiphertextEnvelope{}, err
	}
	if len(oldDEK) != dekSize {
		return CiphertextEnvelope{}, fmt.Errorf("%w: provider returned %d-byte DEK", ErrEnvelopeKeyUnwrap, len(oldDEK))
	}
	wrapped, err := wrapper.Wrap(ctx, newKeyVersion, append([]byte(nil), oldDEK...))
	if err != nil {
		return CiphertextEnvelope{}, fmt.Errorf("%w: %w", ErrEnvelopeKeyWrap, err)
	}
	if len(wrapped) == 0 {
		return CiphertextEnvelope{}, fmt.Errorf("%w: provider returned empty wrapped DEK", ErrEnvelopeKeyWrap)
	}
	out := cloneEnvelope(envelope)
	out.KeyVersion = newKeyVersion
	out.WrappedDEK = append([]byte(nil), wrapped...)
	return out, nil
}

func unwrapAndValidate(ctx context.Context, envelope CiphertextEnvelope, wrapper KeyWrapper) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if wrapper == nil {
		return nil, fmt.Errorf("%w: nil key wrapper", ErrEnvelopeKeyUnwrap)
	}
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	dek, err := wrapper.Unwrap(ctx, envelope.KeyVersion, append([]byte(nil), envelope.WrappedDEK...))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelopeKeyUnwrap, err)
	}
	if len(dek) != dekSize {
		zeroBytes(dek)
		return nil, fmt.Errorf("%w: provider returned %d-byte DEK", ErrEnvelopeKeyUnwrap, len(dek))
	}
	return dek, nil
}

func validateEnvelope(e CiphertextEnvelope) error {
	if e.SchemaVersion != EnvelopeSchemaVersion || e.Algorithm != EnvelopeAlgorithm {
		return ErrUnsupportedEnvelope
	}
	if strings.TrimSpace(e.KeyVersion) == "" || len(e.WrappedDEK) == 0 || len(e.Nonce) != 12 || len(e.Ciphertext) < 16 {
		return ErrInvalidEnvelope
	}
	return validateMetadata(e.Metadata)
}

func validateMetadata(m EnvelopeMetadata) error {
	if err := validateMetadataFields(m); err != nil {
		return err
	}
	if len(m.SHA256Digest) != sha256.Size*2 {
		return fmt.Errorf("%w: invalid SHA-256 digest", ErrInvalidEnvelopeMetadata)
	}
	if _, err := hex.DecodeString(m.SHA256Digest); err != nil {
		return fmt.Errorf("%w: invalid SHA-256 digest: %v", ErrInvalidEnvelopeMetadata, err)
	}
	if m.SHA256Digest != strings.ToLower(m.SHA256Digest) {
		return fmt.Errorf("%w: SHA-256 digest must be lowercase", ErrInvalidEnvelopeMetadata)
	}
	if m.PolicyEpoch == 0 {
		return fmt.Errorf("%w: policy epoch must be non-zero", ErrInvalidEnvelopeMetadata)
	}
	return nil
}

func validateMetadataFields(m EnvelopeMetadata) error {
	for name, value := range map[string]string{"tenant": m.TenantID, "plugin": m.PluginID, "plugin version": m.PluginVersion, "target": m.Target} {
		if strings.TrimSpace(value) == "" || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: empty or invalid %s", ErrInvalidEnvelopeMetadata, name)
		}
	}
	return nil
}

func envelopeAAD(m EnvelopeMetadata) []byte {
	var out bytes.Buffer
	out.WriteString(EnvelopeSchemaVersion)
	for _, value := range []string{m.TenantID, m.PluginID, m.PluginVersion, m.Target, strings.ToLower(m.SHA256Digest)} {
		b := []byte(value)
		_ = binary.Write(&out, binary.BigEndian, uint64(len(b)))
		_, _ = out.Write(b)
	}
	_ = binary.Write(&out, binary.BigEndian, m.PolicyEpoch)
	return out.Bytes()
}

func cloneEnvelope(e CiphertextEnvelope) CiphertextEnvelope {
	e.WrappedDEK = append([]byte(nil), e.WrappedDEK...)
	e.Nonce = append([]byte(nil), e.Nonce...)
	e.Ciphertext = append([]byte(nil), e.Ciphertext...)
	return e
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
