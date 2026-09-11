package crp

// This file defines the CRP signature/trust contract. It intentionally has
// no network, filesystem, or persistence side effects. A control-plane adapter
// is responsible for loading a TrustStore snapshot and persisting rotations.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	SignatureAlgorithmEd25519             = "ed25519"
	SignerOfficial            SignerClass = "official"
	SignerEnterprise          SignerClass = "enterprise"
	SignerCommunity           SignerClass = "community"
	SignerPersonal            SignerClass = "personal"
	SignerTest                SignerClass = "test"
	SignerDevelopment         SignerClass = "development"
	SignerUntrusted           SignerClass = "untrusted"

	VerificationTrusted           VerificationStatus = "trusted"
	VerificationNeedsConfirmation VerificationStatus = "needs_confirmation"
	VerificationRejected          VerificationStatus = "rejected"
)

var (
	ErrSignature            = errors.New("invalid CRP signature")
	ErrUnknownSigner        = errors.New("CRP signer is unknown")
	ErrRevokedSigner        = errors.New("CRP signer has been revoked")
	ErrExpiredSigner        = errors.New("CRP signer key is outside its validity window")
	ErrUntrustedSigner      = errors.New("CRP signer is untrusted")
	ErrConfirmationRequired = errors.New("CRP signature requires explicit administrator confirmation")
	ErrThresholdNotMet      = errors.New("CRP signature threshold is not met")
	ErrTrustRoot            = errors.New("invalid CRP trust root")
	ErrKeyRotation          = errors.New("invalid CRP key rotation")
	ErrKeyRevocation        = errors.New("invalid CRP key revocation")
)

type SignerClass string
type VerificationStatus string

// Signature is an Ed25519 signature over SigningBytes(manifest). Value is
// standard base64 so the JSON representation remains portable across CLIs.
type Signature struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	Value     string    `json:"value"`
	SignedAt  time.Time `json:"signed_at,omitempty"`
}

// TrustKey is a public key registration. NotAfter is inclusive; a zero value
// means no local expiry, though each non-official class is still bounded by
// the root's MaxValidity policy when SignedAt is supplied.
type TrustKey struct {
	ID        string      `json:"id"`
	PublicKey []byte      `json:"public_key"`
	Class     SignerClass `json:"class"`
	NotBefore time.Time   `json:"not_before,omitempty"`
	NotAfter  time.Time   `json:"not_after,omitempty"`
	RevokedAt *time.Time  `json:"revoked_at,omitempty"`
}

type SignaturePolicy struct {
	Threshold int `json:"threshold"`
	Total     int `json:"total"`
}

// TrustRoot binds keys to a namespace. Official and enterprise roots use at
// least 2-of-3 for normal releases and 3-of-5 for high-risk releases; a
// configured policy may be stricter but never weaker.
type TrustRoot struct {
	ID                string          `json:"id"`
	Class             SignerClass     `json:"class"`
	NamespacePrefixes []string        `json:"namespace_prefixes"`
	Keys              []TrustKey      `json:"keys"`
	Policy            SignaturePolicy `json:"policy"`
	HighRiskPolicy    SignaturePolicy `json:"high_risk_policy"`
	MaxValidity       time.Duration   `json:"max_validity"`
}

type TrustStore struct{ roots map[string]TrustRoot }

type VerificationOptions struct {
	Now               time.Time
	HighRisk          bool
	AllowConfirmation bool
}

type SignatureReport struct {
	Status          VerificationStatus
	RootID          string
	Class           SignerClass
	Required        int
	ValidSignatures int
	SeenKeyIDs      []string
	InvalidKeyIDs   []string
	Reasons         []string
}

// SigningBytes returns domain-separated canonical bytes. json.Marshal emits
// struct fields in declaration order and is deterministic for this contract.
func SigningBytes(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal manifest: %v", ErrSignature, err)
	}
	return append([]byte("cheesewaf-crp-manifest-v1\n"), b...), nil
}

func SignManifest(m Manifest, privateKey ed25519.PrivateKey, signedAt time.Time) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Signature{}, fmt.Errorf("%w: private key must be %d bytes", ErrSignature, ed25519.PrivateKeySize)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SignManifestWithKeyID(m, KeyIDForPublicKey(publicKey), privateKey, signedAt)
}

// KeyIDForPublicKey returns the stable content identifier used by the
// convenience signer. Deployments may use an approved human-readable key ID
// through SignManifestWithKeyID.
func KeyIDForPublicKey(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func SignManifestWithKeyID(m Manifest, keyID string, privateKey ed25519.PrivateKey, signedAt time.Time) (Signature, error) {
	if len(privateKey) != ed25519.PrivateKeySize || strings.TrimSpace(keyID) == "" || signedAt.IsZero() {
		return Signature{}, fmt.Errorf("%w: key ID, private key, and signed time are required", ErrSignature)
	}
	sig := Signature{KeyID: strings.TrimSpace(keyID), Algorithm: SignatureAlgorithmEd25519, SignedAt: signedAt.UTC()}
	b, err := signatureSigningBytes(m, sig)
	if err != nil {
		return Signature{}, err
	}
	sig.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, b))
	return sig, nil
}

func signatureSigningBytes(m Manifest, sig Signature) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	payload := struct {
		Manifest  Manifest  `json:"manifest"`
		KeyID     string    `json:"key_id"`
		Algorithm string    `json:"algorithm"`
		SignedAt  time.Time `json:"signed_at"`
	}{m, sig.KeyID, sig.Algorithm, sig.SignedAt.UTC()}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal signed envelope: %v", ErrSignature, err)
	}
	return append([]byte("cheesewaf-crp-signature-v1\n"), b...), nil
}

func NewTrustStore(roots []TrustRoot) (TrustStore, error) {
	out := make(map[string]TrustRoot, len(roots))
	for _, root := range roots {
		root.ID = strings.TrimSpace(root.ID)
		if root.ID == "" || len(root.NamespacePrefixes) == 0 || len(root.Keys) == 0 {
			return TrustStore{}, fmt.Errorf("%w: id, namespace prefixes, and keys are required", ErrTrustRoot)
		}
		if _, exists := out[root.ID]; exists {
			return TrustStore{}, fmt.Errorf("%w: duplicate root %q", ErrTrustRoot, root.ID)
		}
		if err := validateSignerClass(root.Class); err != nil {
			return TrustStore{}, err
		}
		if root.MaxValidity <= 0 {
			root.MaxValidity = defaultMaxValidity(root.Class)
		}
		for i := range root.NamespacePrefixes {
			if err := validateNamespacePrefix(root.NamespacePrefixes[i]); err != nil {
				return TrustStore{}, err
			}
			root.NamespacePrefixes[i] = strings.TrimSuffix(strings.TrimSpace(root.NamespacePrefixes[i]), "/")
			if err := validateRootNamespaceClass(root.Class, root.NamespacePrefixes[i]); err != nil {
				return TrustStore{}, err
			}
		}
		root.Policy, root.HighRiskPolicy = defaultPolicies(root)
		if max := classMaxValidity(root.Class); max > 0 && root.MaxValidity > max {
			return TrustStore{}, fmt.Errorf("%w: max validity %s exceeds class maximum %s", ErrTrustRoot, root.MaxValidity, max)
		}
		if err := validatePolicyForClass(root.Policy, len(root.Keys), false, root.Class, false); err != nil {
			return TrustStore{}, err
		}
		// The built-in official high-risk policy is 3-of-5. A root may be
		// bootstrapped with only its normal 2-of-3 quorum; high-risk admission
		// then remains unavailable until rotation adds the remaining keys.
		if err := validatePolicyForClass(root.HighRiskPolicy, len(root.Keys), root.Class == SignerOfficial && root.HighRiskPolicy == (SignaturePolicy{Threshold: 3, Total: 5}), root.Class, true); err != nil {
			return TrustStore{}, err
		}
		seen := make(map[string]struct{}, len(root.Keys))
		seenPublic := make(map[string]struct{}, len(root.Keys))
		for i := range root.Keys {
			key := &root.Keys[i]
			key.ID = strings.TrimSpace(key.ID)
			if key.ID == "" || len(key.PublicKey) != ed25519.PublicKeySize {
				return TrustStore{}, fmt.Errorf("%w: key %q must contain a %d-byte Ed25519 public key", ErrTrustRoot, key.ID, ed25519.PublicKeySize)
			}
			if _, exists := seen[key.ID]; exists {
				return TrustStore{}, fmt.Errorf("%w: duplicate key %q", ErrTrustRoot, key.ID)
			}
			seen[key.ID] = struct{}{}
			publicID := hex.EncodeToString(key.PublicKey)
			if _, exists := seenPublic[publicID]; exists {
				return TrustStore{}, fmt.Errorf("%w: duplicate public key for %q", ErrTrustRoot, key.ID)
			}
			seenPublic[publicID] = struct{}{}
			if !key.NotBefore.IsZero() && !key.NotAfter.IsZero() {
				if !key.NotAfter.After(key.NotBefore) || (root.MaxValidity > 0 && key.NotAfter.Sub(key.NotBefore) > root.MaxValidity) {
					return TrustStore{}, fmt.Errorf("%w: key %q validity window exceeds root policy", ErrTrustRoot, key.ID)
				}
			}
			if key.Class == "" {
				key.Class = root.Class
			}
			if err := validateSignerClass(key.Class); err != nil {
				return TrustStore{}, err
			}
			key.PublicKey = append([]byte(nil), key.PublicKey...)
		}
		root.NamespacePrefixes = append([]string(nil), root.NamespacePrefixes...)
		root.Keys = cloneTrustKeys(root.Keys)
		out[root.ID] = root
	}
	return TrustStore{roots: out}, nil
}

func validateRootNamespaceClass(class SignerClass, prefix string) error {
	if class == SignerOfficial && prefix != "official" && !strings.HasPrefix(prefix, "official/") {
		return fmt.Errorf("%w: official roots may bind only official namespaces", ErrTrustRoot)
	}
	if class == SignerEnterprise && prefix != "enterprise" && !strings.HasPrefix(prefix, "enterprise/") {
		return fmt.Errorf("%w: enterprise roots may bind only enterprise namespaces", ErrTrustRoot)
	}
	if class != SignerOfficial && class != SignerEnterprise && (prefix == "official" || strings.HasPrefix(prefix, "official/") || prefix == "enterprise" || strings.HasPrefix(prefix, "enterprise/")) {
		return fmt.Errorf("%w: non-production roots may not bind official or enterprise namespaces", ErrTrustRoot)
	}
	return nil
}

func defaultPolicies(root TrustRoot) (SignaturePolicy, SignaturePolicy) {
	normal, high := root.Policy, root.HighRiskPolicy
	if root.Class == SignerOfficial || root.Class == SignerEnterprise {
		if normal == (SignaturePolicy{}) {
			normal = SignaturePolicy{Threshold: 2, Total: 3}
		}
		if high == (SignaturePolicy{}) {
			high = SignaturePolicy{Threshold: 3, Total: 5}
		}
	} else {
		if normal == (SignaturePolicy{}) {
			normal = SignaturePolicy{Threshold: 1, Total: 1}
		}
		if high == (SignaturePolicy{}) {
			high = normal
		}
	}
	return normal, high
}

func defaultMaxValidity(class SignerClass) time.Duration {
	switch class {
	case SignerCommunity, SignerPersonal:
		return 365 * 24 * time.Hour
	case SignerTest:
		return 30 * 24 * time.Hour
	case SignerDevelopment:
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

func classMaxValidity(class SignerClass) time.Duration {
	switch class {
	case SignerEnterprise, SignerOfficial:
		return 3 * 365 * 24 * time.Hour
	case SignerCommunity, SignerPersonal:
		return 365 * 24 * time.Hour
	case SignerTest:
		return 30 * 24 * time.Hour
	case SignerDevelopment:
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

func validatePolicyForClass(policy SignaturePolicy, keyCount int, allowInsufficientKeys bool, class SignerClass, highRisk bool) error {
	if class == SignerOfficial || class == SignerEnterprise {
		minimum := SignaturePolicy{Threshold: 2, Total: 3}
		if highRisk {
			minimum = SignaturePolicy{Threshold: 3, Total: 5}
		}
		if policy.Threshold < minimum.Threshold || policy.Total < minimum.Total {
			return fmt.Errorf("%w: policy %d-of-%d is below platform minimum %d-of-%d", ErrTrustRoot, policy.Threshold, policy.Total, minimum.Threshold, minimum.Total)
		}
	}
	if policy.Threshold < 1 || policy.Total < policy.Threshold || (!allowInsufficientKeys && policy.Total > keyCount) {
		return fmt.Errorf("%w: threshold %d-of-%d with %d keys", ErrTrustRoot, policy.Threshold, policy.Total, keyCount)
	}
	return nil
}

func cloneTrustKeys(keys []TrustKey) []TrustKey {
	cloned := make([]TrustKey, len(keys))
	for i, key := range keys {
		cloned[i] = key
		cloned[i].PublicKey = append([]byte(nil), key.PublicKey...)
		if key.RevokedAt != nil {
			t := key.RevokedAt.UTC()
			cloned[i].RevokedAt = &t
		}
	}
	return cloned
}

func (s TrustStore) Root(id string) (TrustRoot, bool) {
	r, ok := s.roots[strings.TrimSpace(id)]
	if !ok {
		return TrustRoot{}, false
	}
	r.NamespacePrefixes = append([]string(nil), r.NamespacePrefixes...)
	r.Keys = cloneTrustKeys(r.Keys)
	return r, true
}

// VerifyManifest verifies namespace binding, signatures, key lifecycle and
// threshold. Unknown signers are always rejected; explicitly untrusted roots
// can only proceed when AllowConfirmation is true, and remain visibly marked.
func (s TrustStore) VerifyManifest(m Manifest, signatures []Signature, opts VerificationOptions) (SignatureReport, error) {
	report := SignatureReport{Status: VerificationRejected}
	if err := m.Validate(); err != nil {
		return report, err
	}
	root, ok := s.roots[m.SourceRoot]
	if !ok {
		return report, fmt.Errorf("%w: source root %q", ErrUnknownSigner, m.SourceRoot)
	}
	report.RootID, report.Class = root.ID, root.Class
	bound := false
	for _, prefix := range root.NamespacePrefixes {
		if namespaceMatches(m.Namespace, prefix) {
			bound = true
			break
		}
	}
	if !bound {
		return report, fmt.Errorf("%w: namespace %q is not bound to root %q", ErrNamespace, m.Namespace, root.ID)
	}
	policy := root.Policy
	if opts.HighRisk {
		policy = root.HighRiskPolicy
	}
	report.Required = policy.Threshold
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	now := opts.Now.UTC()
	keys := make(map[string]TrustKey, len(root.Keys))
	for _, key := range root.Keys {
		keys[key.ID] = key
	}
	seen := make(map[string]struct{}, len(signatures))
	hasUnknown := false
	hasRevoked := false
	hasExpired := false
	hasBadSignature := false
	for _, sig := range signatures {
		report.SeenKeyIDs = append(report.SeenKeyIDs, sig.KeyID)
		if _, duplicate := seen[sig.KeyID]; duplicate {
			report.Reasons = append(report.Reasons, "duplicate signer "+sig.KeyID)
			continue
		}
		seen[sig.KeyID] = struct{}{}
		key, exists := keys[sig.KeyID]
		if !exists {
			hasUnknown = true
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "unknown signer "+sig.KeyID)
			continue
		}
		if sig.Algorithm != SignatureAlgorithmEd25519 {
			hasBadSignature = true
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "unsupported algorithm "+sig.Algorithm)
			continue
		}
		if key.RevokedAt != nil && !now.Before(key.RevokedAt.UTC()) {
			hasRevoked = true
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "revoked signer "+sig.KeyID)
			continue
		}
		if sig.SignedAt.IsZero() || sig.SignedAt.After(now) {
			hasBadSignature = true
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "missing or future signature timestamp "+sig.KeyID)
			continue
		}
		at := sig.SignedAt.UTC()
		if !key.NotBefore.IsZero() && at.Before(key.NotBefore.UTC()) || !key.NotAfter.IsZero() && at.After(key.NotAfter.UTC()) {
			hasExpired = true
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "expired signer "+sig.KeyID)
			continue
		}
		if root.MaxValidity > 0 && now.Sub(at) > root.MaxValidity {
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "signature exceeds root validity")
			continue
		}
		signedBytes, signedErr := signatureSigningBytes(m, sig)
		raw, decErr := base64.StdEncoding.DecodeString(sig.Value)
		if signedErr != nil || decErr != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key.PublicKey), signedBytes, raw) {
			hasBadSignature = true
			report.InvalidKeyIDs = append(report.InvalidKeyIDs, sig.KeyID)
			report.Reasons = append(report.Reasons, "bad signature "+sig.KeyID)
			continue
		}
		report.ValidSignatures++
		if requiresConfirmation(key.Class) || requiresConfirmation(root.Class) {
			report.Status = VerificationNeedsConfirmation
		}
	}
	if report.ValidSignatures < policy.Threshold {
		if hasUnknown && report.ValidSignatures == 0 {
			return report, ErrUnknownSigner
		}
		var causes []error
		if hasRevoked && report.ValidSignatures == 0 {
			causes = append(causes, ErrRevokedSigner)
		}
		if hasExpired && report.ValidSignatures == 0 {
			causes = append(causes, ErrExpiredSigner)
		}
		if hasBadSignature {
			causes = append(causes, ErrSignature)
		}
		thresholdErr := fmt.Errorf("%w: valid=%d required=%d", ErrThresholdNotMet, report.ValidSignatures, policy.Threshold)
		if len(causes) > 0 {
			causes = append(causes, thresholdErr)
			return report, errors.Join(causes...)
		}
		return report, thresholdErr
	}
	if report.Status == VerificationNeedsConfirmation {
		if !opts.AllowConfirmation {
			return report, ErrConfirmationRequired
		}
		return report, nil
	}
	report.Status = VerificationTrusted
	return report, nil
}

func requiresConfirmation(class SignerClass) bool {
	switch class {
	case SignerCommunity, SignerPersonal, SignerTest, SignerDevelopment, SignerUntrusted:
		return true
	default:
		return false
	}
}

func (s TrustStore) Rotate(rootID string, additions []TrustKey) (TrustStore, error) {
	root, ok := s.roots[rootID]
	if !ok {
		return TrustStore{}, fmt.Errorf("%w: root %q not found", ErrKeyRotation, rootID)
	}
	keys := append([]TrustKey(nil), root.Keys...)
	for _, add := range additions {
		found := false
		for _, key := range keys {
			if key.ID == add.ID {
				found = true
			}
		}
		if found {
			return TrustStore{}, fmt.Errorf("%w: key %q already exists", ErrKeyRotation, add.ID)
		}
		keys = append(keys, add)
	}
	root.Keys = keys
	return NewTrustStore(replaceRoot(s, root))
}

func (s TrustStore) Revoke(rootID, keyID string, at time.Time) (TrustStore, error) {
	root, ok := s.roots[rootID]
	if !ok {
		return TrustStore{}, fmt.Errorf("%w: root %q not found", ErrKeyRevocation, rootID)
	}
	root.Keys = cloneTrustKeys(root.Keys)
	found := false
	for i := range root.Keys {
		if root.Keys[i].ID == keyID {
			if root.Keys[i].RevokedAt != nil {
				return TrustStore{}, fmt.Errorf("%w: key %q already revoked", ErrKeyRevocation, keyID)
			}
			t := at.UTC()
			if t.IsZero() {
				t = time.Now().UTC()
			}
			root.Keys[i].RevokedAt = &t
			found = true
		}
	}
	if !found {
		return TrustStore{}, fmt.Errorf("%w: key %q not found", ErrKeyRevocation, keyID)
	}
	return NewTrustStore(replaceRoot(s, root))
}

func replaceRoot(s TrustStore, root TrustRoot) []TrustRoot {
	out := make([]TrustRoot, 0, len(s.roots))
	for id, existing := range s.roots {
		if id == root.ID {
			out = append(out, root)
		} else {
			out = append(out, existing)
		}
	}
	return out
}

func validateSignerClass(class SignerClass) error {
	switch class {
	case SignerOfficial, SignerEnterprise, SignerCommunity, SignerPersonal, SignerTest, SignerDevelopment, SignerUntrusted:
		return nil
	default:
		return fmt.Errorf("%w: unknown signer class %q", ErrTrustRoot, class)
	}
}

// ContentIdentity returns the SHA-256 identity that higher layers can put in
// transparency logs without storing the artifact bytes.
func ContentIdentity(m Manifest) (string, error) {
	b, err := SigningBytes(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
