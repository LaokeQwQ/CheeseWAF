package extensions

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

var (
	ErrSignerProviderClosed = errors.New("extension signer provider is closed")
	ErrSignerNoActiveKey    = errors.New("extension signer provider has no active key")
	ErrSignerKeyNotFound    = errors.New("extension signer key is not found")
	ErrSignerKeyExists      = errors.New("extension signer key already exists")
	ErrSignerKeyNotUsable   = errors.New("extension signer key is not usable")
)

// SignerProvider is the host-only boundary for extension output signing.
//
// A plugin receives only the serialized AttestedOutput. It never receives
// this interface, a private key, or a private-key snapshot. Implementations
// must keep private key material in the control-plane key lifecycle and may
// use an HSM/KMS-backed signer later without changing the ingress contract.
type SignerProvider interface {
	Sign(context.Context, []byte, time.Time) (AttestedOutput, error)
	TrustSnapshot(context.Context) (TrustSnapshot, error)
}

// TrustSnapshot is a point-in-time public-key view used by Verify and Ingress.
// Keys contains public material only; it is safe to pass across a verifier
// boundary after the caller has applied its tenant/policy binding.
type TrustSnapshot struct {
	Generation  uint64
	ActiveKeyID string
	Keys        map[string]TrustKey
}

// MemorySignerKey is constructor input for the test/development provider.
// The private key is copied into process memory and is never included in a
// TrustSnapshot or serialized by this package. Production key loading remains
// an explicit integration task for a host keystore/HSM/KMS adapter.
type MemorySignerKey struct {
	ID         string
	PrivateKey ed25519.PrivateKey
	NotBefore  time.Time
	NotAfter   time.Time
}

// MemorySignerProvider provides a deterministic host-only provider for tests
// and single-process development. It is intentionally not a KMS adapter.
type MemorySignerProvider struct {
	mu         sync.RWMutex
	keys       map[string]memorySignerKey
	active     string
	generation uint64
	now        func() time.Time
	maxTTL     time.Duration
	clockSkew  time.Duration
	closed     bool
}

type memorySignerKey struct {
	private   ed25519.PrivateKey
	trust     TrustKey
	revokedAt *time.Time
}

type MemorySignerProviderOptions struct {
	Keys        []MemorySignerKey
	ActiveKeyID string
	Now         func() time.Time
	MaxTTL      time.Duration
	ClockSkew   time.Duration
}

func NewMemorySignerProvider(options MemorySignerProviderOptions) (*MemorySignerProvider, error) {
	if len(options.Keys) == 0 || !validID(options.ActiveKeyID) {
		return nil, ErrSignerKeyNotUsable
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	p := &MemorySignerProvider{
		keys:      make(map[string]memorySignerKey, len(options.Keys)),
		now:       options.Now,
		maxTTL:    options.MaxTTL,
		clockSkew: options.ClockSkew,
	}
	for _, input := range options.Keys {
		if err := p.addKeyLocked(input); err != nil {
			p.closeLocked()
			return nil, err
		}
	}
	if _, ok := p.keys[options.ActiveKeyID]; !ok {
		p.closeLocked()
		return nil, ErrSignerKeyNotFound
	}
	p.active = options.ActiveKeyID
	if err := p.validateUsableLocked(p.active, p.now().UTC().Round(0)); err != nil {
		p.closeLocked()
		return nil, err
	}
	p.generation = 1
	return p, nil
}

func (p *MemorySignerProvider) addKeyLocked(input MemorySignerKey) error {
	if p == nil || !validID(input.ID) || len(input.PrivateKey) != ed25519.PrivateKeySize || (!input.NotAfter.IsZero() && !input.NotBefore.IsZero() && !input.NotAfter.After(input.NotBefore)) {
		return ErrSignerKeyNotUsable
	}
	if _, exists := p.keys[input.ID]; exists {
		return ErrSignerKeyExists
	}
	private := append(ed25519.PrivateKey(nil), input.PrivateKey...)
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	p.keys[input.ID] = memorySignerKey{private: private, trust: TrustKey{ID: input.ID, PublicKey: public, NotBefore: input.NotBefore.UTC(), NotAfter: input.NotAfter.UTC()}}
	return nil
}

// Sign signs an unsigned extension payload with the current active key. The
// private key is copied only for the duration of the call and is zeroed after.
func (p *MemorySignerProvider) Sign(ctx context.Context, payload []byte, signedAt time.Time) (AttestedOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return AttestedOutput{}, err
	}
	now := p.currentTime()
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return AttestedOutput{}, ErrSignerProviderClosed
	}
	if p.active == "" {
		p.mu.RUnlock()
		return AttestedOutput{}, ErrSignerNoActiveKey
	}
	entry, ok := p.keys[p.active]
	if !ok {
		p.mu.RUnlock()
		return AttestedOutput{}, ErrSignerNoActiveKey
	}
	keyID := entry.trust.ID
	private := append(ed25519.PrivateKey(nil), entry.private...)
	trust := entry.trust
	p.mu.RUnlock()
	defer zeroPrivate(private)
	if err := validateSignerKeyAt(trust, entry.revokedAt, signedAt.UTC().Round(0), now); err != nil {
		return AttestedOutput{}, err
	}
	return (Signer{KeyID: keyID, PrivateKey: private, Now: func() time.Time { return now }, MaxTTL: p.maxTTL, ClockSkew: p.clockSkew}).Sign(payload, signedAt)
}

// TrustSnapshot returns public keys and lifecycle metadata without exposing
// private key bytes. The returned map and public key slices are independent.
func (p *MemorySignerProvider) TrustSnapshot(ctx context.Context) (TrustSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return TrustSnapshot{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return TrustSnapshot{}, ErrSignerProviderClosed
	}
	out := TrustSnapshot{Generation: p.generation, ActiveKeyID: p.active, Keys: make(map[string]TrustKey, len(p.keys))}
	for id, entry := range p.keys {
		trust := entry.trust
		trust.PublicKey = append(ed25519.PublicKey(nil), entry.trust.PublicKey...)
		if entry.revokedAt != nil {
			at := entry.revokedAt.UTC()
			trust.RevokedAt = &at
		}
		out.Keys[id] = trust
	}
	return out, nil
}

// Rotate activates an already provisioned key. Provisioning and persistence
// are deliberately outside this package; this method only changes the active
// pointer after lifecycle checks pass.
func (p *MemorySignerProvider) Rotate(ctx context.Context, keyID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validID(keyID) {
		return ErrSignerKeyNotFound
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrSignerProviderClosed
	}
	if err := p.validateUsableLocked(keyID, p.now().UTC().Round(0)); err != nil {
		return err
	}
	p.active = keyID
	p.generation++
	return nil
}

// Revoke prevents future signing with a key while retaining its public
// metadata in snapshots so already-issued outputs can be audited explicitly.
func (p *MemorySignerProvider) Revoke(ctx context.Context, keyID string, revokedAt time.Time) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validID(keyID) || revokedAt.IsZero() || revokedAt.Nanosecond() != 0 {
		return ErrSignerKeyNotUsable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrSignerProviderClosed
	}
	entry, ok := p.keys[keyID]
	if !ok {
		return ErrSignerKeyNotFound
	}
	at := revokedAt.UTC().Round(0)
	entry.revokedAt = &at
	entry.trust.RevokedAt = &at
	p.keys[keyID] = entry
	if p.active == keyID {
		p.active = ""
		p.generation++
	}
	return nil
}

// Close zeroes process-resident private keys. It does not claim to erase
// copies held by an OS allocator or an external keystore.
func (p *MemorySignerProvider) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closeLocked()
	return nil
}

func (p *MemorySignerProvider) validateUsableLocked(keyID string, now time.Time) error {
	entry, ok := p.keys[keyID]
	if !ok {
		return ErrSignerKeyNotFound
	}
	return validateSignerKeyAt(entry.trust, entry.revokedAt, now, now)
}

func validateSignerKeyAt(key TrustKey, revokedAt *time.Time, signedAt, now time.Time) error {
	if revokedAt != nil && !now.Before(revokedAt.UTC()) {
		return ErrKeyRevoked
	}
	if !key.NotBefore.IsZero() && signedAt.Before(key.NotBefore.UTC()) {
		return ErrKeyOutsideValidity
	}
	if !key.NotAfter.IsZero() && (signedAt.After(key.NotAfter.UTC()) || !now.Before(key.NotAfter.UTC())) {
		return ErrKeyOutsideValidity
	}
	return nil
}

func (p *MemorySignerProvider) currentTime() time.Time {
	if p == nil || p.now == nil {
		return time.Now().UTC().Round(0)
	}
	return p.now().UTC().Round(0)
}

func (p *MemorySignerProvider) closeLocked() {
	for id, entry := range p.keys {
		zeroPrivate(entry.private)
		delete(p.keys, id)
	}
	p.active = ""
	p.closed = true
}

func zeroPrivate(key ed25519.PrivateKey) {
	for i := range key {
		key[i] = 0
	}
}
