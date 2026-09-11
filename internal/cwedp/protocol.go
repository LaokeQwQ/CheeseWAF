// Package cwedp contains the pure protocol contract for CheeseWAF Edge
// Distribution Protocol. It intentionally performs no I/O.
package cwedp

import (
	"crypto/md5"  // #nosec G501 -- compatibility integrity digest, not security.
	"crypto/sha1" // #nosec G505 -- compatibility integrity digest, not security.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

const ProtocolVersion = "cwedp/v1"

const (
	// These are hard platform ceilings. A deployment may choose lower values
	// but may not widen them through a peer-provided capability message.
	DefaultMaxChunkBytes     int64 = 8 << 20
	DefaultMaxArtifactBytes  int64 = 1 << 30
	DefaultMaxSourceSwitches       = 3
)

type SourceKind string

const (
	SourceOTA     SourceKind = "ota"
	SourceSeed    SourceKind = "seed"
	SourcePeer    SourceKind = "peer"
	SourceOffline SourceKind = "offline-crp"
)

type Digests struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}
type Source struct {
	Kind                   SourceKind `json:"kind"`
	ID                     string     `json:"id"`
	TrustRoot              string     `json:"trust_root,omitempty"`
	Organization           string     `json:"organization,omitempty"`
	CertificateFingerprint string     `json:"certificate_fingerprint,omitempty"`
}

// QuarantineReason is intentionally a closed set.  Persisting arbitrary
// transport error strings would make the resume record both unstable and a
// potential place to leak credentials or request data.
type QuarantineReason string

const (
	QuarantineIntegrity QuarantineReason = "integrity-mismatch"
	QuarantineTransport QuarantineReason = "transport-failure"
	QuarantinePolicy    QuarantineReason = "policy-failure"
)

// SourceQuarantine records a source that must not be selected again for this
// intent.  The source identity is the (kind, ID) pair; the other fields are
// retained to make the audit/revalidation input explicit.
type SourceQuarantine struct {
	Source Source           `json:"source"`
	Reason QuarantineReason `json:"reason"`
}

// SourceRegistration is the trusted control-plane record for a source ID.
// Source fields in a DistributionIntent are untrusted claims and are not used
// to establish provenance.
type SourceRegistration struct {
	ID                string
	Kind              SourceKind
	Root              string
	IndependenceGroup string
}

// SourceRegistry is an immutable snapshot of authorized source provenance.
type SourceRegistry struct {
	entries map[string]SourceRegistration
}

func NewSourceRegistry(registrations []SourceRegistration) (SourceRegistry, error) {
	entries := make(map[string]SourceRegistration, len(registrations))
	for _, registration := range registrations {
		if !validSourceKind(registration.Kind) || !validRegistrationField(registration.ID) || !validRegistrationField(registration.Root) || !validRegistrationField(registration.IndependenceGroup) {
			return SourceRegistry{}, ErrInvalid
		}
		registration.ID = strings.TrimSpace(registration.ID)
		registration.Root = strings.TrimSpace(registration.Root)
		registration.IndependenceGroup = strings.TrimSpace(registration.IndependenceGroup)
		if !validIdentifier(registration.ID) || !validIdentifier(registration.Root) || !validIdentifier(registration.IndependenceGroup) {
			return SourceRegistry{}, ErrInvalid
		}
		if _, exists := entries[registration.ID]; exists {
			return SourceRegistry{}, ErrInvalid
		}
		entries[registration.ID] = registration
	}
	return SourceRegistry{entries: entries}, nil
}

func validRegistrationField(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	trimmed := strings.TrimSpace(value)
	return validIdentifier(trimmed)
}

type DistributionIntent struct {
	ID, PackageID, Version string
	Size                   int64
	Digests                Digests
	Sources                []Source
	Signature              string
}

// IntentSignatureVerifier is the admission hook for the opaque intent
// signature. Transport never interprets the signature bytes or chooses keys.
type IntentSignatureVerifier interface {
	Verify(DistributionIntent) error
}

type IntentSignatureVerifierFunc func(DistributionIntent) error

func (f IntentSignatureVerifierFunc) Verify(intent DistributionIntent) error {
	return f(intent)
}

type Hello struct {
	NodeID, Protocol string
	Offline          bool
}
type Capabilities struct {
	NodeID           string
	ProtocolVersions []string
	Sources          []SourceKind
	MaxChunkSize     int64
}

var (
	ErrInvalid            = errors.New("invalid CWEDP message")
	ErrOfflineSource      = errors.New("offline node has no permitted source")
	ErrNoSource           = errors.New("no mutually supported distribution source")
	ErrChunkOverlap       = errors.New("chunk overlaps or is out of order")
	ErrChunkSize          = errors.New("chunk exceeds configured size")
	ErrFailureLimit       = errors.New("distribution failure limit exhausted")
	ErrSourceIndependence = errors.New("distribution sources are not independent")
	ErrSourceQuarantined  = errors.New("distribution source is quarantined")
	ErrSourceSwitchLimit  = errors.New("distribution source switch limit exhausted")
	ErrStateConflict      = errors.New("distribution resume state conflicts with persisted intent")
	ErrIntentSignature    = errors.New("distribution intent signature is required")
)

func (d Digests) valid() bool {
	return validLowerHex(d.MD5, 32) && validLowerHex(d.SHA1, 40) && validLowerHex(d.SHA256, 64)
}

func validLowerHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validSourceKind(kind SourceKind) bool {
	switch kind {
	case SourceOTA, SourceSeed, SourcePeer, SourceOffline:
		return true
	default:
		return false
	}
}

// validIdentifier rejects leading/trailing and invisible whitespace instead
// of silently normalising an identifier.  Protocol IDs are used as database
// keys and audit subjects, so accepting a visually equivalent spelling would
// make resume and provenance checks ambiguous.
func validIdentifier(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func sourceKey(source Source) string {
	return string(source.Kind) + "\x00" + source.ID
}

func validQuarantineReason(reason QuarantineReason) bool {
	switch reason {
	case QuarantineIntegrity, QuarantineTransport, QuarantinePolicy:
		return true
	default:
		return false
	}
}

// ValidateSourceQuarantines validates a persisted quarantine list without
// modifying it. Quarantine entries are keyed by source kind and ID; metadata
// claims from the transfer are never used as trust evidence.
func ValidateSourceQuarantines(intent DistributionIntent, quarantines []SourceQuarantine) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(quarantines))
	for _, quarantine := range quarantines {
		if !sourceKeyInIntent(intent, quarantine.Source) || !validQuarantineReason(quarantine.Reason) {
			return ErrInvalid
		}
		if (quarantine.Source.TrustRoot != "" && !validIdentifier(quarantine.Source.TrustRoot)) || (quarantine.Source.Organization != "" && !validIdentifier(quarantine.Source.Organization)) || (quarantine.Source.CertificateFingerprint != "" && !validIdentifier(quarantine.Source.CertificateFingerprint)) {
			return ErrInvalid
		}
		key := sourceKey(quarantine.Source)
		if _, exists := seen[key]; exists {
			return ErrInvalid
		}
		seen[key] = struct{}{}
	}
	return nil
}

// AddSourceQuarantine returns a copied list and is idempotent for a repeated
// (source, reason) report. A source cannot be silently un-quarantined or have
// its original reason overwritten by a later retry.
func AddSourceQuarantine(intent DistributionIntent, existing []SourceQuarantine, source Source, reason QuarantineReason) ([]SourceQuarantine, error) {
	if err := intent.Validate(); err != nil {
		return nil, err
	}
	if !sourceKeyInIntent(intent, source) || !validQuarantineReason(reason) {
		return nil, ErrInvalid
	}
	if err := ValidateSourceQuarantines(intent, existing); err != nil {
		return nil, err
	}
	result := append([]SourceQuarantine(nil), existing...)
	for _, entry := range result {
		if sourceKey(entry.Source) == sourceKey(source) {
			return result, nil
		}
	}
	// Persist the canonical source spelling from the intent, not arbitrary
	// metadata supplied by a failure reporter.
	for _, candidate := range intent.Sources {
		if sourceKey(candidate) == sourceKey(source) {
			result = append(result, SourceQuarantine{Source: candidate, Reason: reason})
			return result, nil
		}
	}
	return nil, ErrInvalid
}

func quarantineReasonFor(quarantines []SourceQuarantine, source Source) (QuarantineReason, bool) {
	key := sourceKey(source)
	for _, entry := range quarantines {
		if sourceKey(entry.Source) == key {
			return entry.Reason, true
		}
	}
	return "", false
}

// SelectSource chooses the first negotiated candidate that is not quarantined.
// If current is supplied and still usable it is preferred, which makes resume
// deterministic and avoids gratuitous source switching.
func SelectSource(intent DistributionIntent, hello Hello, capabilities Capabilities, current *Source, quarantines []SourceQuarantine) (Source, error) {
	if err := intent.Validate(); err != nil {
		return Source{}, err
	}
	if err := ValidateSourceQuarantines(intent, quarantines); err != nil {
		return Source{}, err
	}
	if err := hello.Validate(); err != nil {
		return Source{}, err
	}
	if err := capabilities.Validate(); err != nil {
		return Source{}, err
	}
	if hello.NodeID != capabilities.NodeID {
		return Source{}, ErrInvalid
	}
	quarantined := make(map[string]struct{}, len(quarantines))
	for _, entry := range quarantines {
		quarantined[sourceKey(entry.Source)] = struct{}{}
	}
	blockedCandidate := false
	usable := func(candidate Source) bool {
		if _, blocked := quarantined[sourceKey(candidate)]; blocked {
			blockedCandidate = true
			return false
		}
		if hello.Offline && candidate.Kind != SourceOffline {
			return false
		}
		return supports(capabilities, candidate.Kind)
	}
	if current != nil && usable(*current) && sourceInIntent(intent, *current) {
		return *current, nil
	}
	for _, candidate := range intent.Sources {
		if usable(candidate) {
			return candidate, nil
		}
	}
	if current != nil {
		if _, blocked := quarantined[sourceKey(*current)]; blocked {
			return Source{}, ErrSourceQuarantined
		}
	}
	if blockedCandidate {
		return Source{}, ErrSourceQuarantined
	}
	if hello.Offline {
		return Source{}, ErrOfflineSource
	}
	return Source{}, ErrNoSource
}

func sourceInIntent(intent DistributionIntent, source Source) bool {
	for _, candidate := range intent.Sources {
		if candidate == source {
			return true
		}
	}
	return false
}

func sourceKeyInIntent(intent DistributionIntent, source Source) bool {
	for _, candidate := range intent.Sources {
		if sourceKey(candidate) == sourceKey(source) {
			return true
		}
	}
	return false
}

func (i DistributionIntent) Validate() error {
	if i.Signature == "" {
		return ErrIntentSignature
	}
	if !validIdentifier(i.ID) || !validIdentifier(i.PackageID) || !validIdentifier(i.Version) || !validIdentifier(i.Signature) || i.Size < 0 || i.Size > DefaultMaxArtifactBytes || !i.Digests.valid() || len(i.Sources) == 0 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, s := range i.Sources {
		if !validIdentifier(s.ID) || !validSourceKind(s.Kind) || seen[sourceKey(s)] {
			return ErrInvalid
		}
		if (s.TrustRoot != "" && !validIdentifier(s.TrustRoot)) || (s.Organization != "" && !validIdentifier(s.Organization)) || (s.CertificateFingerprint != "" && !validIdentifier(s.CertificateFingerprint)) {
			return ErrInvalid
		}
		seen[sourceKey(s)] = true
	}
	return nil
}
func (h Hello) Validate() error {
	if !validIdentifier(h.NodeID) || h.Protocol != ProtocolVersion {
		return ErrInvalid
	}
	return nil
}
func (c Capabilities) Validate() error {
	if !validIdentifier(c.NodeID) || c.MaxChunkSize <= 0 || c.MaxChunkSize > DefaultMaxChunkBytes || len(c.ProtocolVersions) == 0 {
		return ErrInvalid
	}
	seenProtocols := make(map[string]struct{}, len(c.ProtocolVersions))
	for _, p := range c.ProtocolVersions {
		if !validIdentifier(p) {
			return ErrInvalid
		}
		if _, duplicate := seenProtocols[p]; duplicate {
			return ErrInvalid
		}
		seenProtocols[p] = struct{}{}
	}
	for _, p := range c.ProtocolVersions {
		if p == ProtocolVersion {
			seenSources := make(map[SourceKind]struct{}, len(c.Sources))
			for _, kind := range c.Sources {
				if !validSourceKind(kind) {
					return ErrInvalid
				}
				if _, duplicate := seenSources[kind]; duplicate {
					return ErrInvalid
				}
				seenSources[kind] = struct{}{}
			}
			return nil
		}
	}
	return ErrInvalid
}
func supports(c Capabilities, k SourceKind) bool {
	for _, x := range c.Sources {
		if x == k {
			return true
		}
	}
	return false
}
func Negotiate(i DistributionIntent, h Hello, c Capabilities) (Source, error) {
	if err := i.Validate(); err != nil {
		return Source{}, err
	}
	if err := h.Validate(); err != nil {
		return Source{}, err
	}
	if err := c.Validate(); err != nil {
		return Source{}, err
	}
	if h.NodeID != c.NodeID {
		return Source{}, ErrInvalid
	}
	for _, s := range i.Sources {
		if h.Offline && s.Kind != SourceOffline {
			continue
		}
		if supports(c, s.Kind) {
			return s, nil
		}
	}
	if h.Offline {
		return Source{}, ErrOfflineSource
	}
	return Source{}, ErrNoSource
}
func ValidateSourceIndependence(i DistributionIntent, registry SourceRegistry) error {
	return ValidateSourceIndependenceWithMinimum(i, registry, 2)
}

// ValidateSourceIndependenceWithMinimum verifies source provenance and allows
// a trusted deployment policy to choose one or two independent roots. The
// default remains two; selecting one is an explicit low-risk/observe policy
// at the broker boundary and cannot widen the platform's maximum.
func ValidateSourceIndependenceWithMinimum(i DistributionIntent, registry SourceRegistry, minimum int) error {
	if err := i.Validate(); err != nil {
		return err
	}
	if minimum < 1 || minimum > 2 {
		return ErrSourceIndependence
	}
	roots := map[string]bool{}
	groups := map[string]bool{}
	for _, s := range i.Sources {
		registration, ok := registry.entries[s.ID]
		if !ok || registration.Kind != s.Kind || strings.TrimSpace(registration.Root) == "" || strings.TrimSpace(registration.IndependenceGroup) == "" {
			return ErrSourceIndependence
		}
		// A source is independent only when both its supply-chain root and
		// registered independence group are new.  Different URLs/types do not
		// make mirrors independent, and a registry typo cannot widen trust.
		if roots[registration.Root] || groups[registration.IndependenceGroup] {
			continue
		}
		roots[registration.Root] = true
		groups[registration.IndependenceGroup] = true
	}
	if len(groups) < minimum {
		return ErrSourceIndependence
	}
	return nil
}

type TransferState struct {
	mu              sync.Mutex
	size, next, max int64
}

func NewTransferState(size, maxChunk int64) *TransferState {
	return &TransferState{size: size, max: maxChunk}
}
func (s *TransferState) Accept(offset, length int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if length <= 0 || length > s.max {
		return ErrChunkSize
	}
	if offset != s.next || offset < 0 || offset > s.size || length > s.size-offset {
		return ErrChunkOverlap
	}
	s.next += length
	return nil
}
func (s *TransferState) NextOffset() int64 { s.mu.Lock(); defer s.mu.Unlock(); return s.next }
func (s *TransferState) Complete() bool    { s.mu.Lock(); defer s.mu.Unlock(); return s.next == s.size }
func VerifyDigests(data []byte, w Digests) error {
	m := md5.Sum(data)
	a := sha1.Sum(data)
	h := sha256.Sum256(data)
	got := Digests{hex.EncodeToString(m[:]), hex.EncodeToString(a[:]), hex.EncodeToString(h[:])}
	if !w.valid() || got.MD5 != w.MD5 || got.SHA1 != w.SHA1 || got.SHA256 != w.SHA256 {
		return fmt.Errorf("%w: digest mismatch", ErrInvalid)
	}
	return nil
}

type FailureBudget struct {
	mu        sync.Mutex
	remaining int
}

func NewFailureBudget(max int) *FailureBudget {
	if max < 0 {
		max = 0
	}
	return &FailureBudget{remaining: max}
}
func (b *FailureBudget) Record() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return ErrFailureLimit
	}
	b.remaining--
	return nil
}
func (b *FailureBudget) Failed() bool    { return b.Record() != nil }
func (b *FailureBudget) Exhausted() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.remaining == 0 }
