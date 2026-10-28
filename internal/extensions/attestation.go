// Package extensions implements the host-owned attestation used for
// asynchronous Jev, EDR, and DuckDB extension outputs.
//
// It deliberately has no network, filesystem, or key-persistence side
// effects. The control plane supplies a signer and the verifier receives a
// snapshot of trusted public keys.
package extensions

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	AlgorithmEd25519 = "ed25519"
	IssuerHost       = "cheesewaf-host"
	Purpose          = "extension-output-attestation"
	Domain           = "cheesewaf-extension-output-attestation-v1"
	DefaultMaxTTL    = time.Hour
	DefaultClockSkew = 30 * time.Second
)

var (
	ErrInvalidPayload      = errors.New("invalid extension output payload")
	ErrInvalidAttestation  = errors.New("invalid extension output attestation")
	ErrUnknownKey          = errors.New("extension attestation key is unknown")
	ErrKeyRevoked          = errors.New("extension attestation key is revoked")
	ErrKeyOutsideValidity  = errors.New("extension attestation key is outside its validity window")
	ErrSignatureInvalid    = errors.New("extension output signature is invalid")
	ErrPayloadDigest       = errors.New("extension output payload digest does not match")
	ErrIssuedAtFuture      = errors.New("extension output attestation is from the future")
	ErrExpired             = errors.New("extension output has expired")
	ErrTTLExceeded         = errors.New("extension output ttl exceeds policy")
	ErrPolicyEpochMismatch = errors.New("extension output policy epoch does not match")
	ErrScopeMismatch       = errors.New("extension output scope does not match")
	ErrClaimsMalformed     = errors.New("extension output claims are malformed")
)

// RejectionCode is safe to put in an audit event. It intentionally contains
// no attacker-controlled identifiers or payload values.
type RejectionCode string

const (
	RejectInvalidPayload      RejectionCode = "extension.output.invalid_payload"
	RejectInvalidAttestation  RejectionCode = "extension.output.invalid_attestation"
	RejectUnknownKey          RejectionCode = "extension.output.unknown_key"
	RejectKeyRevoked          RejectionCode = "extension.output.key_revoked"
	RejectKeyOutsideValidity  RejectionCode = "extension.output.key_outside_validity"
	RejectSignatureInvalid    RejectionCode = "extension.output.signature_invalid"
	RejectPayloadDigest       RejectionCode = "extension.output.payload_digest_mismatch"
	RejectIssuedAtFuture      RejectionCode = "extension.output.issued_at_future"
	RejectExpired             RejectionCode = "extension.output.expired"
	RejectTTLExceeded         RejectionCode = "extension.output.ttl_exceeded"
	RejectPolicyEpochMismatch RejectionCode = "extension.output.policy_epoch_mismatch"
	RejectScopeMismatch       RejectionCode = "extension.output.scope_mismatch"
	RejectClaimsMalformed     RejectionCode = "extension.output.claims_malformed"
)

// RejectionError carries an auditable, bounded failure code. Its Error string
// never includes payload, key material, or arbitrary plugin-controlled text.
type RejectionError struct {
	Code RejectionCode
	err  error
}

func (e RejectionError) Error() string { return string(e.Code) }
func (e RejectionError) Unwrap() error { return e.err }

func reject(code RejectionCode, err error) error { return RejectionError{Code: code, err: err} }

// AuditCode extracts a stable code for an audit event. Unknown errors are
// deliberately collapsed to a generic code.
func AuditCode(err error) string {
	var rejected RejectionError
	if errors.As(err, &rejected) && rejected.Code != "" {
		return string(rejected.Code)
	}
	return string(RejectInvalidAttestation)
}

// Integrity is the host-owned field embedded in each extension output.
type Integrity struct {
	Algorithm     string    `json:"algorithm"`
	Issuer        string    `json:"issuer"`
	Purpose       string    `json:"purpose"`
	Domain        string    `json:"domain"`
	KeyID         string    `json:"key_id"`
	SignedAt      time.Time `json:"signed_at"`
	PayloadSHA256 string    `json:"payload_sha256"`
	Value         string    `json:"value"`
}

// AttestedOutput keeps the canonical unsigned payload separate from its
// integrity object. MarshalJSON combines them into the Plugin wire shape.
type AttestedOutput struct {
	Payload   json.RawMessage
	Integrity Integrity
}

func (o AttestedOutput) MarshalJSON() ([]byte, error) {
	payload, err := canonicalPayload(o.Payload)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return nil, ErrInvalidPayload
	}
	if _, exists := object["integrity"]; exists {
		return nil, ErrInvalidPayload
	}
	integrity, err := json.Marshal(o.Integrity)
	if err != nil {
		return nil, err
	}
	object["integrity"] = integrity
	return json.Marshal(object)
}

// Parse decodes a Plugin message and removes the integrity field before
// canonicalizing the payload used for digest and signature verification.
func Parse(raw []byte) (AttestedOutput, error) {
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return AttestedOutput{}, reject(RejectInvalidPayload, ErrInvalidPayload)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(canonical, &object) != nil || object == nil {
		return AttestedOutput{}, reject(RejectInvalidPayload, ErrInvalidPayload)
	}
	integrityRaw, ok := object["integrity"]
	if !ok {
		return AttestedOutput{}, reject(RejectInvalidAttestation, ErrInvalidAttestation)
	}
	delete(object, "integrity")
	payload, err := json.Marshal(object)
	if err != nil {
		return AttestedOutput{}, reject(RejectInvalidPayload, ErrInvalidPayload)
	}
	var integrity Integrity
	if err := decodeStrict(integrityRaw, &integrity); err != nil {
		return AttestedOutput{}, reject(RejectInvalidAttestation, ErrInvalidAttestation)
	}
	return AttestedOutput{Payload: payload, Integrity: integrity}, nil
}

// Signer holds one control-plane signing key. Private keys must be loaded by
// the caller from its key lifecycle implementation and are never persisted by
// this package.
type Signer struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
	Now        func() time.Time
	MaxTTL     time.Duration
	ClockSkew  time.Duration
}

// Sign creates a host attestation over an unsigned JSON object. The input may
// have arbitrary whitespace; its canonical form is what gets signed.
func (s Signer) Sign(payload []byte, signedAt time.Time) (AttestedOutput, error) {
	canonical, err := canonicalPayload(payload)
	if err != nil {
		return AttestedOutput{}, reject(RejectInvalidPayload, ErrInvalidPayload)
	}
	if !validID(s.KeyID) || len(s.PrivateKey) != ed25519.PrivateKeySize || signedAt.IsZero() || signedAt.Nanosecond() != 0 {
		return AttestedOutput{}, reject(RejectInvalidAttestation, ErrInvalidAttestation)
	}
	signedAt = signedAt.UTC().Round(0)
	now := signedAt
	if s.Now != nil {
		now = s.Now().UTC().Round(0)
	}
	skew := s.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if signedAt.After(now.Add(skew)) {
		return AttestedOutput{}, reject(RejectIssuedAtFuture, ErrIssuedAtFuture)
	}
	if err := verifyClaims(canonical, signedAt, now, VerifyOptions{Now: now, MaxTTL: s.MaxTTL, ClockSkew: s.ClockSkew}); err != nil {
		return AttestedOutput{}, err
	}
	digest := digestJSON(canonical)
	value := base64.StdEncoding.EncodeToString(ed25519.Sign(s.PrivateKey, SigningBytes(digest, s.KeyID, signedAt)))
	return AttestedOutput{Payload: canonical, Integrity: Integrity{
		Algorithm: AlgorithmEd25519, Issuer: IssuerHost, Purpose: Purpose, Domain: Domain,
		KeyID: s.KeyID, SignedAt: signedAt, PayloadSHA256: digest, Value: value,
	}}, nil
}

// TrustKey is a public key snapshot supplied by the control plane verifier.
type TrustKey struct {
	ID        string
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	RevokedAt *time.Time
}

// VerifyOptions contains current policy and scope expectations. All supplied
// scope fields must match claims present in the output.
type VerifyOptions struct {
	Now         time.Time
	MaxTTL      time.Duration
	ClockSkew   time.Duration
	PolicyEpoch uint64
	TenantRef   string
	SiteRef     string
	SubjectHash string
}

// Verify validates the exact Plugin host-attestation contract and common
// risk-hint/event claims. It returns a bounded RejectionError suitable for an
// audit record; callers must discard the output on any error.
func Verify(output AttestedOutput, keys map[string]TrustKey, options VerifyOptions) error {
	canonical, err := canonicalPayload(output.Payload)
	if err != nil || !bytes.Equal(canonical, output.Payload) {
		return reject(RejectInvalidPayload, ErrInvalidPayload)
	}
	integrity := output.Integrity
	if integrity.Algorithm != AlgorithmEd25519 || integrity.Issuer != IssuerHost || integrity.Purpose != Purpose || integrity.Domain != Domain || !validID(integrity.KeyID) || integrity.SignedAt.IsZero() || integrity.SignedAt.Nanosecond() != 0 || len(integrity.Value) == 0 {
		return reject(RejectInvalidAttestation, ErrInvalidAttestation)
	}
	if digestJSON(canonical) != integrity.PayloadSHA256 {
		return reject(RejectPayloadDigest, ErrPayloadDigest)
	}
	key, ok := keys[integrity.KeyID]
	if !ok || key.ID != integrity.KeyID {
		return reject(RejectUnknownKey, ErrUnknownKey)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return reject(RejectUnknownKey, ErrUnknownKey)
	}
	now := options.Now.UTC().Round(0)
	if now.IsZero() {
		now = time.Now().UTC().Round(0)
	}
	if key.RevokedAt != nil && !now.Before(key.RevokedAt.UTC()) {
		return reject(RejectKeyRevoked, ErrKeyRevoked)
	}
	signedAt := integrity.SignedAt.UTC().Round(0)
	if !key.NotBefore.IsZero() && signedAt.Before(key.NotBefore.UTC()) || !key.NotAfter.IsZero() && (signedAt.After(key.NotAfter.UTC()) || now.After(key.NotAfter.UTC())) {
		return reject(RejectKeyOutsideValidity, ErrKeyOutsideValidity)
	}
	skew := options.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if signedAt.After(now.Add(skew)) {
		return reject(RejectIssuedAtFuture, ErrIssuedAtFuture)
	}
	signature, err := base64.StdEncoding.DecodeString(integrity.Value)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, SigningBytes(integrity.PayloadSHA256, integrity.KeyID, signedAt), signature) {
		return reject(RejectSignatureInvalid, ErrSignatureInvalid)
	}
	if err := verifyClaims(canonical, signedAt, now, options); err != nil {
		return err
	}
	return nil
}

func verifyClaims(payload []byte, signedAt, now time.Time, options VerifyOptions) error {
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || claims == nil {
		return reject(RejectClaimsMalformed, ErrClaimsMalformed)
	}
	if options.PolicyEpoch != 0 {
		var epoch uint64
		raw, ok := claims["policy_epoch"]
		if !ok || json.Unmarshal(raw, &epoch) != nil || epoch != options.PolicyEpoch {
			return reject(RejectPolicyEpochMismatch, ErrPolicyEpochMismatch)
		}
	}
	skew := options.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if raw, ok := claims["expires_at"]; ok {
		var expiry time.Time
		if json.Unmarshal(raw, &expiry) != nil || expiry.IsZero() {
			return reject(RejectClaimsMalformed, ErrClaimsMalformed)
		}
		issued := now
		if rawIssued, exists := claims["observed_at"]; exists {
			if json.Unmarshal(rawIssued, &issued) != nil || issued.IsZero() {
				return reject(RejectClaimsMalformed, ErrClaimsMalformed)
			}
			if issued.After(now.Add(skew)) {
				return reject(RejectIssuedAtFuture, ErrIssuedAtFuture)
			}
		}
		if !expiry.After(issued) {
			return reject(RejectTTLExceeded, ErrTTLExceeded)
		}
		max := maxTTL(options.MaxTTL)
		if max > 0 && expiry.Sub(issued) > max {
			return reject(RejectTTLExceeded, ErrTTLExceeded)
		}
		if !now.Before(expiry) {
			return reject(RejectExpired, ErrExpired)
		}
	}
	for _, field := range []string{"observed_at", "generated_at", "created_at"} {
		if raw, ok := claims[field]; ok {
			var at time.Time
			if json.Unmarshal(raw, &at) != nil || at.IsZero() {
				return reject(RejectClaimsMalformed, ErrClaimsMalformed)
			}
			if at.After(now.Add(skew)) {
				return reject(RejectIssuedAtFuture, ErrIssuedAtFuture)
			}
			if signedAt.Before(at.UTC()) {
				return reject(RejectIssuedAtFuture, ErrIssuedAtFuture)
			}
		}
	}
	if options.TenantRef != "" || options.SiteRef != "" || options.SubjectHash != "" {
		var tenant, site, subject string
		_ = json.Unmarshal(claims["tenant_ref"], &tenant)
		_ = json.Unmarshal(claims["site_ref"], &site)
		var subjectObject struct {
			SiteRef     string `json:"site_ref"`
			SubjectHash string `json:"subject_hash"`
		}
		if raw, ok := claims["subject"]; ok {
			if json.Unmarshal(raw, &subjectObject) != nil {
				return reject(RejectClaimsMalformed, ErrClaimsMalformed)
			}
		}
		if site == "" {
			site = subjectObject.SiteRef
		}
		if subject == "" {
			subject = subjectObject.SubjectHash
		}
		if (options.TenantRef != "" && tenant != options.TenantRef) || (options.SiteRef != "" && site != options.SiteRef) || (options.SubjectHash != "" && subject != options.SubjectHash) {
			return reject(RejectScopeMismatch, ErrScopeMismatch)
		}
	}
	return nil
}

// SigningBytes exposes the exact cross-language attestation input for test
// vectors and independent verifiers.
func SigningBytes(payloadDigest, keyID string, signedAt time.Time) []byte {
	return []byte(Domain + "\n" + payloadDigest + "\n" + keyID + "\n" + signedAt.UTC().Format(time.RFC3339))
}

func canonicalPayload(raw []byte) ([]byte, error) {
	payload, err := canonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || object == nil {
		return nil, ErrInvalidPayload
	}
	if _, exists := object["integrity"]; exists {
		return nil, ErrInvalidPayload
	}
	return payload, nil
}

// CanonicalPayload returns the compact, sorted-key JSON bytes used for the
// payload digest. The value must be a top-level JSON object without integrity.
func CanonicalPayload(raw []byte) ([]byte, error) { return canonicalPayload(raw) }

// PayloadDigest returns the SHA-256 digest of CanonicalPayload in lowercase
// hexadecimal form.
func PayloadDigest(raw []byte) (string, error) {
	payload, err := canonicalPayload(raw)
	if err != nil {
		return "", err
	}
	return digestJSON(payload), nil
}

func canonicalJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, ErrInvalidPayload
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, ErrInvalidPayload
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrInvalidPayload
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "")
	if err := encoder.Encode(value); err != nil {
		return nil, ErrInvalidPayload
	}
	encoded := out.Bytes()
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		return nil, ErrInvalidPayload
	}
	return encoded[:len(encoded)-1], nil
}

func digestJSON(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func maxTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultMaxTTL
	}
	return ttl
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(value, "..") {
		return false
	}
	for _, c := range value {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(":/._@+-", c) {
			continue
		}
		return false
	}
	return true
}

func decodeStrict(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
