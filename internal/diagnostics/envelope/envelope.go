// Package envelope implements the application-side diagnostic encryption
// contract. It deliberately has no persistence or object-storage dependency.
// Callers must provide a key provider; there is no implicit plaintext path.
package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unicode"
	"unicode/utf8"
)

const (
	SchemaVersion = "diagnostic-envelope.v1"
	Algorithm     = "AES-256-GCM"

	DEKSize        = 32
	NonceSize      = 12
	GCMTagSize     = 16
	EnvelopeIDSize = 16
	DEKBytes       = DEKSize
	NonceBytes     = NonceSize
	AuthTagSize    = GCMTagSize

	// Finite limits stop malformed persisted records from causing unbounded
	// allocation. They are contract limits, not a storage implementation.
	MaxMetadataFieldBytes = 1024
	MaxKeyVersionBytes    = 256
	MaxEnvelopeIDBytes    = 128
	MaxWrappedDEKBytes    = 16 << 10
	MaxPlaintextBytes     = 64 << 20
	MaxCiphertextBytes    = MaxPlaintextBytes + GCMTagSize
	MaxEnvelopeJSONBytes  = 96 << 20
)

// Compatibility names used by earlier diagnostics contracts.
const (
	EnvelopeSchemaVersion = SchemaVersion
	EnvelopeAlgorithm     = Algorithm
)

var (
	ErrInvalidEnvelope        = errors.New("invalid diagnostic envelope")
	ErrInvalidMetadata        = errors.New("invalid diagnostic envelope metadata")
	ErrUnsupportedEnvelope    = errors.New("unsupported diagnostic envelope")
	ErrDigestMismatch         = errors.New("diagnostic envelope digest mismatch")
	ErrKeyWrap                = errors.New("diagnostic envelope key wrapping failed")
	ErrKeyUnwrap              = errors.New("diagnostic envelope key unwrapping failed")
	ErrAuthentication         = errors.New("diagnostic envelope authentication failed")
	ErrReplay                 = errors.New("diagnostic envelope replay rejected")
	ErrReplayReservation      = errors.New("diagnostic envelope replay reservation missing")
	ErrReplayGuardUnavailable = errors.New("diagnostic envelope replay guard unavailable")
	ErrReplayGuardFull        = errors.New("diagnostic envelope replay guard full")
	ErrProviderClosed         = errors.New("diagnostic envelope key provider is closed")
	ErrProviderUnavailable    = errors.New("diagnostic envelope key provider unavailable")
	ErrProviderKeyNotFound    = errors.New("diagnostic envelope key version unavailable")
	ErrKeyVersionExists       = errors.New("diagnostic envelope key version already exists")
	ErrKeyRotationNoop        = errors.New("diagnostic envelope key rotation requires a new key version")
	ErrInvalidProvider        = errors.New("invalid diagnostic envelope key provider")
)

// Compatibility aliases for the root diagnostics naming convention.
var (
	ErrInvalidEnvelopeMetadata = ErrInvalidMetadata
	ErrEnvelopeDigestMismatch  = ErrDigestMismatch
	ErrEnvelopeKeyWrap         = ErrKeyWrap
	ErrEnvelopeKeyUnwrap       = ErrKeyUnwrap
	ErrEnvelopeAuthentication  = ErrAuthentication
	ErrInvalidNonce            = ErrInvalidEnvelope
	ErrInvalidLength           = ErrInvalidEnvelope
	ErrAADMismatch             = ErrAuthentication
	ErrReplayDetected          = ErrReplay
)

// KeyProvider abstracts an external KMS/HSM. Providers own KEK material; the
// envelope package only handles an ephemeral per-package DEK.
type KeyProvider interface {
	Wrap(context.Context, string, []byte) ([]byte, error)
	Unwrap(context.Context, string, []byte) ([]byte, error)
}

// Availability is optional for external KMS adapters. Providers that expose
// it can be probed before an operation; adapters without it are treated as an
// explicitly supplied external dependency and are not silently replaced.
type Availability interface {
	Available(context.Context) bool
}

// OfflineMarker identifies an in-process fallback provider. It is deliberately
// separate from Availability so an external KMS cannot accidentally be treated
// as a local fallback.
type OfflineMarker interface {
	OfflineOnly() bool
}

// SelectProvider prefers an available external KMS. A local/embedded provider
// is selected only when embeddedApproved is true; unavailable providers never
// create a plaintext bypass.
func SelectProvider(external, embedded KeyProvider, embeddedApproved bool) (KeyProvider, error) {
	if external != nil && providerAvailable(external) && !providerIsOffline(external) {
		return external, nil
	}
	if embeddedApproved && embedded != nil && providerAvailable(embedded) {
		return embedded, nil
	}
	return nil, ErrProviderUnavailable
}

func providerAvailable(provider KeyProvider) bool {
	if isNilInterface(provider) {
		return false
	}
	if probe, ok := provider.(Availability); ok {
		return probe.Available(context.Background())
	}
	return true
}

func providerIsOffline(provider KeyProvider) bool {
	marker, ok := provider.(OfflineMarker)
	return ok && marker.OfflineOnly()
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// DEKProvider is an alternate external-KMS spelling used by adapters that
// name the operations explicitly. Adapt it with NewDEKProviderAdapter.
type DEKProvider interface {
	WrapDEK(context.Context, string, []byte) ([]byte, error)
	UnwrapDEK(context.Context, string, []byte) ([]byte, error)
}

type dekProviderAdapter struct{ provider DEKProvider }

func (a dekProviderAdapter) Wrap(ctx context.Context, version string, dek []byte) ([]byte, error) {
	return a.provider.WrapDEK(ctx, version, dek)
}

func (a dekProviderAdapter) Unwrap(ctx context.Context, version string, wrapped []byte) ([]byte, error) {
	return a.provider.UnwrapDEK(ctx, version, wrapped)
}

// NewDEKProviderAdapter makes an explicit adapter for an external KMS using
// WrapDEK/UnwrapDEK method names. A nil provider is rejected.
func NewDEKProviderAdapter(provider DEKProvider) (KeyProvider, error) {
	if isNilInterface(provider) {
		return nil, ErrInvalidProvider
	}
	return dekProviderAdapter{provider: provider}, nil
}

// KeyWrapper and KMS are compatibility aliases. There is no implicit provider
// selection: a caller must explicitly pass an external KMS or LocalProvider.
type Provider = KeyProvider
type KeyWrapper = KeyProvider
type KMS = KeyProvider

// Metadata is authenticated as AEAD additional authenticated data (AAD).
type Metadata struct {
	TenantID      string `json:"tenant_id"`
	PluginID      string `json:"plugin_id"`
	PluginVersion string `json:"plugin_version"`
	Target        string `json:"target"`
	SHA256Digest  string `json:"sha256"`
	PolicyEpoch   uint64 `json:"policy_epoch"`
}

// Envelope contains only authenticated metadata, a wrapped DEK, a nonce, and
// ciphertext. It never stores plaintext package bytes. ID and EnvelopeID are
// duplicate compatibility spellings and are equal when emitted by Seal.
type Envelope struct {
	ID            string   `json:"id,omitempty"`
	EnvelopeID    string   `json:"envelope_id,omitempty"`
	SchemaVersion string   `json:"schema_version"`
	Algorithm     string   `json:"algorithm"`
	KeyVersion    string   `json:"key_version"`
	WrappedDEK    []byte   `json:"wrapped_dek"`
	Nonce         []byte   `json:"nonce"`
	Ciphertext    []byte   `json:"ciphertext"`
	Metadata      Metadata `json:"metadata"`
}

// Compatibility aliases.
type CiphertextEnvelope = Envelope
type EnvelopeMetadata = Metadata

// ReplayGuard is the legacy one-shot replay barrier. OpenOnce authenticates
// before invoking CheckAndMark so tampered data cannot consume a replay slot.
type ReplayGuard interface {
	CheckAndMark(context.Context, string) error
}

// TransactionalReplayGuard separates admission from completion. Integrations
// should reserve only after authentication, release when the external side
// effect fails, and commit after it succeeds. This prevents a transient upload
// failure from consuming the identity while still suppressing concurrent use.
// Implementations must make Reserve atomic with respect to the envelope ID.
type TransactionalReplayGuard interface {
	Reserve(context.Context, string) error
	Commit(context.Context, string) error
	Release(context.Context, string) error
}

// Validate checks all framing, metadata, nonce, and bounded-length invariants
// without invoking a key provider.
func Validate(envelope Envelope) error {
	return validateEnvelope(envelope)
}

// AAD returns the canonical authenticated-data encoding for an envelope. It is
// useful to external providers that want to audit the exact binding, but callers
// normally should let Seal/Open construct it internally.
func AAD(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	return envelopeAAD(envelope), nil
}

// Decode parses one JSON envelope using a strict schema and validates it before
// returning. It rejects unknown fields and trailing JSON values.
func Decode(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeJSONBytes {
		return Envelope{}, fmt.Errorf("%w: encoded envelope length out of bounds", ErrInvalidEnvelope)
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Envelope{}, fmt.Errorf("%w: trailing JSON", ErrInvalidEnvelope)
	}
	if err := validateEnvelope(envelope); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

// Encode validates and serializes an envelope. The resulting JSON contains
// base64-encoded wrapped key, nonce, and ciphertext fields, never plaintext.
func Encode(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// Seal encrypts one package with a fresh random DEK and asks provider to wrap
// that DEK under keyVersion. A nil provider is always an error.
func Seal(ctx context.Context, plaintext []byte, metadata Metadata, keyVersion string, provider KeyProvider) (Envelope, error) {
	if err := contextErr(ctx); err != nil {
		return Envelope{}, err
	}
	if isNilInterface(provider) {
		return Envelope{}, fmt.Errorf("%w: nil provider", ErrKeyWrap)
	}
	if len(plaintext) > MaxPlaintextBytes {
		return Envelope{}, fmt.Errorf("%w: plaintext length %d exceeds %d", ErrInvalidEnvelope, len(plaintext), MaxPlaintextBytes)
	}
	if err := validateKeyVersion(keyVersion); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrKeyWrap, err)
	}
	digest := sha256.Sum256(plaintext)
	digestHex := hex.EncodeToString(digest[:])
	if metadata.SHA256Digest != "" && metadata.SHA256Digest != digestHex {
		return Envelope{}, ErrDigestMismatch
	}
	metadata.SHA256Digest = digestHex
	if err := validateMetadata(metadata); err != nil {
		return Envelope{}, err
	}

	id, err := randomEnvelopeID()
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: generate envelope identity: %v", ErrInvalidEnvelope, err)
	}
	dek := make([]byte, DEKSize)
	defer zeroBytes(dek)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Envelope{}, fmt.Errorf("%w: generate DEK: %v", ErrKeyWrap, err)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: initialize cipher: %v", ErrInvalidEnvelope, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: initialize AEAD: %v", ErrInvalidEnvelope, err)
	}
	nonce := make([]byte, NonceSize)
	defer zeroBytes(nonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("%w: generate nonce: %v", ErrInvalidEnvelope, err)
	}
	envelope := Envelope{ID: id, EnvelopeID: id, SchemaVersion: SchemaVersion, Algorithm: Algorithm, KeyVersion: keyVersion, Metadata: metadata}
	aad := envelopeAAD(envelope)
	defer zeroBytes(aad)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	defer zeroBytes(ciphertext)

	wrapInput := cloneBytes(dek)
	defer zeroBytes(wrapInput)
	wrapped, err := provider.Wrap(ctx, keyVersion, wrapInput)
	if err != nil {
		if wrapped != nil {
			zeroBytes(wrapped)
		}
		return Envelope{}, fmt.Errorf("%w: %w", ErrKeyWrap, err)
	}
	if err := contextErr(ctx); err != nil {
		zeroBytes(wrapped)
		return Envelope{}, err
	}
	if err := validateWrappedDEK(wrapped); err != nil {
		zeroBytes(wrapped)
		return Envelope{}, fmt.Errorf("%w: %v", ErrKeyWrap, err)
	}
	ownedWrapped := cloneBytes(wrapped)
	zeroBytes(wrapped)
	envelope.WrappedDEK = ownedWrapped
	envelope.Nonce = cloneBytes(nonce)
	envelope.Ciphertext = cloneBytes(ciphertext)
	return envelope, nil
}

// SealEnvelope is a compatibility spelling for Seal.
func SealEnvelope(ctx context.Context, plaintext []byte, metadata Metadata, keyVersion string, provider KeyProvider) (Envelope, error) {
	return Seal(ctx, plaintext, metadata, keyVersion, provider)
}

// Encrypt is a concise compatibility spelling for Seal.
func Encrypt(ctx context.Context, plaintext []byte, metadata Metadata, keyVersion string, provider KeyProvider) (Envelope, error) {
	return Seal(ctx, plaintext, metadata, keyVersion, provider)
}

// Open authenticates and decrypts an envelope. The returned plaintext belongs
// to the caller and should be wiped after use.
func Open(ctx context.Context, envelope Envelope, provider KeyProvider) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if isNilInterface(provider) {
		return nil, fmt.Errorf("%w: nil provider", ErrKeyUnwrap)
	}
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	dek, err := unwrapDEK(ctx, envelope, provider)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	return openWithDEK(envelope, dek)
}

// OpenEnvelope is a compatibility spelling for Open.
func OpenEnvelope(ctx context.Context, envelope Envelope, provider KeyProvider) ([]byte, error) {
	return Open(ctx, envelope, provider)
}

// Decrypt is a concise compatibility spelling for Open.
func Decrypt(ctx context.Context, envelope Envelope, provider KeyProvider) ([]byte, error) {
	return Open(ctx, envelope, provider)
}

// Verify authenticates and checks the digest without retaining plaintext.
func Verify(ctx context.Context, envelope Envelope, provider KeyProvider) error {
	plaintext, err := Open(ctx, envelope, provider)
	if plaintext != nil {
		zeroBytes(plaintext)
	}
	return err
}

// VerifyEnvelope is a compatibility spelling for Verify.
func VerifyEnvelope(ctx context.Context, envelope Envelope, provider KeyProvider) error {
	return Verify(ctx, envelope, provider)
}

// OpenOnce authenticates an envelope and atomically rejects a second use of
// its identity. Authentication occurs before the replay mark.
func OpenOnce(ctx context.Context, envelope Envelope, provider KeyProvider, guard ReplayGuard) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if isNilInterface(guard) {
		return nil, ErrReplayGuardUnavailable
	}
	plaintext, err := Open(ctx, envelope, provider)
	if err != nil {
		return nil, err
	}
	id, err := canonicalEnvelopeID(envelope)
	if err != nil {
		zeroBytes(plaintext)
		return nil, err
	}
	if err := guard.CheckAndMark(ctx, id); err != nil {
		zeroBytes(plaintext)
		return nil, err
	}
	return plaintext, nil
}

// DecryptOnce is a concise compatibility spelling for OpenOnce.
func DecryptOnce(ctx context.Context, envelope Envelope, provider KeyProvider, guard ReplayGuard) ([]byte, error) {
	return OpenOnce(ctx, envelope, provider, guard)
}

// OpenAndConsume is a compatibility spelling for OpenOnce.
func OpenAndConsume(ctx context.Context, envelope Envelope, provider KeyProvider, guard ReplayGuard) ([]byte, error) {
	return OpenOnce(ctx, envelope, provider, guard)
}

// Rewrap rotates only the KEK wrapping. Package ciphertext, nonce and identity
// remain unchanged, so rotation can be resumed without re-encrypting payloads.
func Rewrap(ctx context.Context, envelope Envelope, newKeyVersion string, provider KeyProvider) (Envelope, error) {
	if err := contextErr(ctx); err != nil {
		return Envelope{}, err
	}
	if isNilInterface(provider) {
		return Envelope{}, fmt.Errorf("%w: nil provider", ErrKeyUnwrap)
	}
	if err := validateKeyVersion(newKeyVersion); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrKeyWrap, err)
	}
	if err := validateEnvelope(envelope); err != nil {
		return Envelope{}, err
	}
	if newKeyVersion == envelope.KeyVersion {
		return Envelope{}, ErrKeyRotationNoop
	}
	dek, err := unwrapDEK(ctx, envelope, provider)
	if err != nil {
		return Envelope{}, err
	}
	defer zeroBytes(dek)
	plaintext, err := openWithDEK(envelope, dek)
	if plaintext != nil {
		zeroBytes(plaintext)
	}
	if err != nil {
		return Envelope{}, err
	}
	wrapInput := cloneBytes(dek)
	defer zeroBytes(wrapInput)
	wrapped, err := provider.Wrap(ctx, newKeyVersion, wrapInput)
	if err != nil {
		if wrapped != nil {
			zeroBytes(wrapped)
		}
		return Envelope{}, fmt.Errorf("%w: %w", ErrKeyWrap, err)
	}
	if err := contextErr(ctx); err != nil {
		zeroBytes(wrapped)
		return Envelope{}, err
	}
	if err := validateWrappedDEK(wrapped); err != nil {
		zeroBytes(wrapped)
		return Envelope{}, fmt.Errorf("%w: %v", ErrKeyWrap, err)
	}
	ownedWrapped := cloneBytes(wrapped)
	zeroBytes(wrapped)
	out := cloneEnvelope(envelope)
	zeroBytes(out.WrappedDEK)
	out.WrappedDEK = ownedWrapped
	out.KeyVersion = newKeyVersion
	return out, nil
}

// RewrapEnvelope is a compatibility spelling for Rewrap.
func RewrapEnvelope(ctx context.Context, envelope Envelope, newKeyVersion string, provider KeyProvider) (Envelope, error) {
	return Rewrap(ctx, envelope, newKeyVersion, provider)
}

// RotateKey is a concise compatibility spelling for Rewrap.
func RotateKey(ctx context.Context, envelope Envelope, newKeyVersion string, provider KeyProvider) (Envelope, error) {
	return Rewrap(ctx, envelope, newKeyVersion, provider)
}

func unwrapDEK(ctx context.Context, envelope Envelope, provider KeyProvider) ([]byte, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	input := cloneBytes(envelope.WrappedDEK)
	defer zeroBytes(input)
	dek, err := provider.Unwrap(ctx, envelope.KeyVersion, input)
	if err != nil {
		if dek != nil {
			zeroBytes(dek)
		}
		return nil, fmt.Errorf("%w: %w", ErrKeyUnwrap, err)
	}
	if len(dek) != DEKSize {
		zeroBytes(dek)
		return nil, fmt.Errorf("%w: provider returned %d-byte DEK", ErrKeyUnwrap, len(dek))
	}
	ownedDEK := cloneBytes(dek)
	zeroBytes(dek)
	if err := contextErr(ctx); err != nil {
		zeroBytes(ownedDEK)
		return nil, err
	}
	return ownedDEK, nil
}

func openWithDEK(envelope Envelope, dek []byte) ([]byte, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("%w: invalid DEK length", ErrAuthentication)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid DEK: %v", ErrAuthentication, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize AEAD: %v", ErrAuthentication, err)
	}
	if len(envelope.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("%w: invalid nonce length", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) < aead.Overhead() {
		return nil, fmt.Errorf("%w: ciphertext shorter than authentication tag", ErrInvalidEnvelope)
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, envelopeAAD(envelope))
	if err != nil {
		if plaintext != nil {
			zeroBytes(plaintext)
		}
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	digest := sha256.Sum256(plaintext)
	expected, decodeErr := hex.DecodeString(envelope.Metadata.SHA256Digest)
	if decodeErr != nil || len(expected) != sha256.Size || subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		zeroBytes(plaintext)
		return nil, ErrDigestMismatch
	}
	return plaintext, nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.SchemaVersion != SchemaVersion || envelope.Algorithm != Algorithm {
		return ErrUnsupportedEnvelope
	}
	if _, err := canonicalEnvelopeID(envelope); err != nil {
		return err
	}
	if err := validateKeyVersion(envelope.KeyVersion); err != nil {
		return err
	}
	if err := validateWrappedDEK(envelope.WrappedDEK); err != nil {
		return fmt.Errorf("%w: wrapped DEK: %v", ErrInvalidEnvelope, err)
	}
	if len(envelope.Nonce) != NonceSize {
		return fmt.Errorf("%w: nonce must be %d bytes", ErrInvalidEnvelope, NonceSize)
	}
	if allZero(envelope.Nonce) {
		return fmt.Errorf("%w: nonce must not be all zero", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) < GCMTagSize || len(envelope.Ciphertext) > MaxCiphertextBytes {
		return fmt.Errorf("%w: ciphertext length out of bounds", ErrInvalidEnvelope)
	}
	return validateMetadata(envelope.Metadata)
}

func validateMetadata(metadata Metadata) error {
	for name, value := range map[string]string{
		"tenant": metadata.TenantID, "plugin": metadata.PluginID,
		"plugin version": metadata.PluginVersion, "target": metadata.Target,
	} {
		if err := validateBoundedText(name, value, MaxMetadataFieldBytes); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidMetadata, err)
		}
	}
	if metadata.PolicyEpoch == 0 {
		return fmt.Errorf("%w: policy epoch must be non-zero", ErrInvalidMetadata)
	}
	if len(metadata.SHA256Digest) != sha256.Size*2 {
		return fmt.Errorf("%w: SHA-256 digest must be %d hex characters", ErrInvalidMetadata, sha256.Size*2)
	}
	if metadata.SHA256Digest != stringLower(metadata.SHA256Digest) {
		return fmt.Errorf("%w: SHA-256 digest must be lowercase", ErrInvalidMetadata)
	}
	if _, err := hex.DecodeString(metadata.SHA256Digest); err != nil {
		return fmt.Errorf("%w: invalid SHA-256 digest: %v", ErrInvalidMetadata, err)
	}
	return nil
}

func validateKeyVersion(version string) error {
	if err := validateBoundedText("key version", version, MaxKeyVersionBytes); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	return nil
}

func validateWrappedDEK(wrapped []byte) error {
	if len(wrapped) == 0 || len(wrapped) > MaxWrappedDEKBytes {
		return fmt.Errorf("wrapped DEK length %d outside 1..%d", len(wrapped), MaxWrappedDEKBytes)
	}
	return nil
}

func validateBoundedText(name, value string, max int) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if len(value) == 0 {
		return fmt.Errorf("%s is empty", name)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", name, max)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s contains whitespace/control/invisible characters", name)
		}
	}
	return nil
}

func canonicalEnvelopeID(envelope Envelope) (string, error) {
	id := envelope.ID
	if id == "" {
		id = envelope.EnvelopeID
	}
	if envelope.ID != "" && envelope.EnvelopeID != "" && envelope.ID != envelope.EnvelopeID {
		return "", fmt.Errorf("%w: envelope identity fields differ", ErrInvalidEnvelope)
	}
	if len(id) != EnvelopeIDSize*2 || len(id) > MaxEnvelopeIDBytes {
		return "", fmt.Errorf("%w: envelope id must be %d lowercase hex characters", ErrInvalidEnvelope, EnvelopeIDSize*2)
	}
	if id != stringLower(id) {
		return "", fmt.Errorf("%w: envelope id must be lowercase", ErrInvalidEnvelope)
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", fmt.Errorf("%w: invalid envelope id: %v", ErrInvalidEnvelope, err)
	}
	return id, nil
}

func randomEnvelopeID() (string, error) {
	raw := make([]byte, EnvelopeIDSize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func envelopeAAD(envelope Envelope) []byte {
	var out bytes.Buffer
	out.WriteString("diagnostic-envelope-aad.v1")
	id := envelope.ID
	if id == "" {
		id = envelope.EnvelopeID
	}
	for _, value := range []string{
		envelope.SchemaVersion, envelope.Algorithm, id,
		envelope.Metadata.TenantID, envelope.Metadata.PluginID,
		envelope.Metadata.PluginVersion, envelope.Metadata.Target, envelope.Metadata.SHA256Digest,
	} {
		writeAADString(&out, value)
	}
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], envelope.Metadata.PolicyEpoch)
	_, _ = out.Write(epoch[:])
	return out.Bytes()
}

func writeAADString(out *bytes.Buffer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = out.Write(length[:])
	_, _ = out.WriteString(value)
}

func cloneEnvelope(envelope Envelope) Envelope {
	envelope.WrappedDEK = cloneBytes(envelope.WrappedDEK)
	envelope.Nonce = cloneBytes(envelope.Nonce)
	envelope.Ciphertext = cloneBytes(envelope.Ciphertext)
	return envelope
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func allZero(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func stringLower(value string) string {
	const upperA, upperZ = 'A', 'Z'
	buf := []byte(value)
	for i, c := range buf {
		if c >= upperA && c <= upperZ {
			buf[i] = c + ('a' - upperA)
		}
	}
	return string(buf)
}
