package kms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Risk string

const (
	RiskHigh Risk = "high"
)

type IssueRequest struct {
	Actor, Scope string
	Risk         Risk
	TTL          time.Duration
}
type Credential struct {
	ID, Secret, Scope string
	ExpiresAt         time.Time
}

type Proof struct{ AdminID, ConfirmationID, SessionID string }
type ProofVerifier interface {
	Verify(context.Context, Proof) error
}
type TemporaryRevoker interface {
	RevokeTemporary(context.Context, string) error
}
type RecoveryRestorer interface {
	Restore(context.Context, string, []byte) error
}

type CredentialOption func(*credentialConfig)

func WithCredentialAuthorizer(a Authorizer) CredentialOption {
	return func(c *credentialConfig) { c.authorizer = a }
}
func WithCredentialAudit(a AuditSink) CredentialOption {
	return func(c *credentialConfig) { c.audit = a }
}
func WithProofVerifier(v ProofVerifier) CredentialOption {
	return func(c *credentialConfig) { c.verifier = v }
}
func WithRecoveryHooks(r TemporaryRevoker, restore RecoveryRestorer) CredentialOption {
	return func(c *credentialConfig) { c.revoker = r; c.restorer = restore }
}
func WithCredentialClock(now func() time.Time) CredentialOption {
	return func(c *credentialConfig) { c.now = now }
}

type credentialConfig struct {
	authorizer Authorizer
	audit      AuditSink
	verifier   ProofVerifier
	revoker    TemporaryRevoker
	restorer   RecoveryRestorer
	now        func() time.Time
}
type credentialRecord struct {
	ID, Scope string
	ExpiresAt time.Time
	Wrapped   []byte
	Digest    [32]byte
	Admins    map[string]struct{}
	Used      map[string]struct{}
	Consumed  bool
}
type CredentialManager struct {
	mu      sync.Mutex
	admins  map[string]struct{}
	records map[string]*credentialRecord
	used    map[string]struct{}
	backend *KeyringBackend
	ref     KeyRef
	cfg     credentialConfig
}

// NewCredentialManager creates a recovery credential service. Sensitive
// authorization and proof checks are deny-by-default when options are omitted.
func NewCredentialManager(admins []string, keyring *EncryptedKeyring, options ...CredentialOption) (*CredentialManager, error) {
	if keyring == nil {
		return nil, ErrInvalidConfig
	}
	cfg := credentialConfig{now: func() time.Time { return time.Now().UTC() }}
	for _, o := range options {
		if o != nil {
			o(&cfg)
		}
	}
	if cfg.authorizer == nil || cfg.audit == nil || cfg.verifier == nil {
		return nil, ErrInvalidConfig
	}
	set := make(map[string]struct{}, len(admins))
	for _, a := range admins {
		if !strict(a) {
			return nil, ErrInvalidConfig
		}
		if _, ok := set[a]; ok {
			return nil, ErrInvalidConfig
		}
		set[a] = struct{}{}
	}
	if len(set) != 3 {
		return nil, ErrInvalidConfig
	}
	ref := KeyRef{TenantID: "recovery", KeyID: "credential", Version: "v1"}
	if _, err := keyring.Get(context.Background(), ref); err != nil {
		if !errors.Is(err, ErrVersion) {
			return nil, err
		}
		k := make([]byte, DEKSize)
		if _, err := rand.Read(k); err != nil {
			return nil, ErrProviderFailure
		}
		if err := keyring.Put(context.Background(), ref, k); err != nil {
			return nil, err
		}
	}
	return &CredentialManager{admins: set, records: make(map[string]*credentialRecord), used: make(map[string]struct{}), backend: NewKeyringBackend(keyring), ref: ref, cfg: cfg}, nil
}

func (m *CredentialManager) Issue(ctx context.Context, req IssueRequest) (Credential, error) {
	if m == nil || req.Risk != RiskHigh || !strict(req.Actor) || !strict(req.Scope) {
		return Credential{}, ErrInvalidInput
	}
	if req.TTL <= 0 {
		req.TTL = 30 * time.Minute
	}
	if req.TTL > 30*time.Minute {
		return Credential{}, ErrInvalidInput
	}
	now := m.cfg.now().UTC()
	if now.IsZero() {
		return Credential{}, ErrInvalidInput
	}
	a := Access{Binding: Binding{TenantID: m.ref.TenantID, KeyID: m.ref.KeyID, Scope: req.Scope, Actor: req.Actor, PolicyEpoch: 1}, Operation: IssueRecovery, Version: m.ref.Version, At: now}
	if err := m.authorize(ctx, a, Embedded); err != nil {
		return Credential{}, err
	}
	secret := make([]byte, DEKSize)
	if _, err := rand.Read(secret); err != nil {
		return Credential{}, ErrProviderFailure
	}
	encodedSecret := EncodeSecret(secret)
	digest := sha256.Sum256(secret)
	wrapped, err := m.backend.Wrap(ctx, m.ref, secret)
	zero(secret)
	if err != nil {
		return Credential{}, ErrProviderFailure
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return Credential{}, ErrProviderFailure
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	m.mu.Lock()
	m.records[id] = &credentialRecord{ID: id, Scope: req.Scope, ExpiresAt: now.Add(req.TTL), Wrapped: append([]byte(nil), wrapped...), Digest: digest, Admins: make(map[string]struct{}), Used: make(map[string]struct{})}
	m.mu.Unlock()
	if err := m.finish(ctx, a, Embedded); err != nil {
		return Credential{}, err
	}
	return Credential{ID: id, Secret: encodedSecret, Scope: req.Scope, ExpiresAt: now.Add(req.TTL)}, nil
}

// Confirm records one independently verified administrator confirmation. The
// confirmation ID is globally single-use, including across recovery requests.
func (m *CredentialManager) Confirm(ctx context.Context, id, adminID, confirmationID string) error {
	if m == nil || !strict(id) || !strict(adminID) || !strict(confirmationID) {
		return ErrInvalidInput
	}
	m.mu.Lock()
	r, ok := m.records[id]
	if !ok {
		m.mu.Unlock()
		return ErrVersion
	}
	if r.Consumed {
		m.mu.Unlock()
		return ErrRecoveryConsumed
	}
	now := m.cfg.now().UTC()
	if !now.Before(r.ExpiresAt) {
		m.mu.Unlock()
		return ErrRecoveryExpired
	}
	if _, ok := m.admins[adminID]; !ok {
		m.mu.Unlock()
		return ErrPermission
	}
	if _, ok := m.used[confirmationID]; ok {
		m.mu.Unlock()
		return ErrReplay
	}
	m.mu.Unlock()
	if err := m.cfg.verifier.Verify(ctx, Proof{AdminID: adminID, ConfirmationID: confirmationID}); err != nil {
		return ErrPermission
	}
	a := Access{Binding: Binding{TenantID: m.ref.TenantID, KeyID: m.ref.KeyID, Scope: r.Scope, Actor: adminID, PolicyEpoch: 1}, Operation: Recover, Version: m.ref.Version, At: now}
	if err := m.authorize(ctx, a, Embedded); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Consumed {
		return ErrRecoveryConsumed
	}
	if !m.cfg.now().UTC().Before(r.ExpiresAt) {
		return ErrRecoveryExpired
	}
	if _, ok := m.used[confirmationID]; ok {
		return ErrReplay
	}
	m.used[confirmationID] = struct{}{}
	r.Admins[adminID] = struct{}{}
	r.Used[confirmationID] = struct{}{}
	return nil
}

// RecoverWithCredential requires possession of the one-time credential in
// addition to the administrator confirmation. The credential is never stored
// in plaintext and is cleared before this method returns.
func (m *CredentialManager) RecoverWithCredential(ctx context.Context, id, encodedSecret, adminID, confirmationID string) (string, error) {
	secret, err := DecodeSecret(encodedSecret)
	if err != nil {
		return "", err
	}
	defer zero(secret)
	m.mu.Lock()
	r, ok := m.records[id]
	if !ok {
		m.mu.Unlock()
		return "", ErrVersion
	}
	digest := r.Digest
	m.mu.Unlock()
	if sha256.Sum256(secret) != digest {
		return "", ErrAuthentication
	}
	if err := m.Confirm(ctx, id, adminID, confirmationID); err != nil {
		return "", err
	}
	m.mu.Lock()
	r = m.records[id]
	if len(r.Admins) < 2 {
		n := len(r.Admins)
		m.mu.Unlock()
		return "", fmt.Errorf("%w: %d of 2", ErrThreshold, n)
	}
	if r.Consumed {
		m.mu.Unlock()
		return "", ErrRecoveryConsumed
	}
	r.Consumed = true
	wrapped := append([]byte(nil), r.Wrapped...)
	scope := r.Scope
	digest = r.Digest
	m.mu.Unlock()
	a := Access{Binding: Binding{TenantID: m.ref.TenantID, KeyID: m.ref.KeyID, Scope: scope, Actor: adminID, PolicyEpoch: 1}, Operation: Recover, Version: m.ref.Version, At: m.cfg.now().UTC()}
	if err := m.auditEvent(ctx, a, Embedded, "recovery-claimed"); err != nil {
		return "", err
	}
	unwrapped, err := m.backend.Unwrap(ctx, m.ref, wrapped)
	if err != nil {
		return "", ErrProviderFailure
	}
	defer zero(unwrapped)
	if sha256.Sum256(unwrapped) != digest || !bytes.Equal(unwrapped, secret) {
		zero(unwrapped)
		return "", ErrAuthentication
	}
	if m.cfg.revoker != nil {
		if err := m.cfg.revoker.RevokeTemporary(ctx, id); err != nil {
			return "", ErrProviderFailure
		}
	}
	if m.cfg.restorer != nil {
		if err := m.cfg.restorer.Restore(ctx, id, append([]byte(nil), unwrapped...)); err != nil {
			return "", ErrProviderFailure
		}
	}
	if err := m.auditEvent(ctx, a, Embedded, "recovered"); err != nil {
		return "", err
	}
	return EncodeSecret(unwrapped), nil
}

// Recover is intentionally disabled because an identifier and two approvals
// are not proof of possession of the portable recovery credential.
func (m *CredentialManager) Recover(context.Context, string, string, string) (string, error) {
	return "", ErrInvalidInput
}

func (m *CredentialManager) authorize(ctx context.Context, a Access, kind ProviderKind) error {
	if err := m.cfg.authorizer.Authorize(ctx, a); err != nil {
		_ = m.auditEvent(ctx, a, kind, "denied")
		return ErrPermission
	}
	return m.auditEvent(ctx, a, kind, "attempt")
}
func (m *CredentialManager) finish(ctx context.Context, a Access, kind ProviderKind) error {
	return m.auditEvent(ctx, a, kind, "succeeded")
}
func (m *CredentialManager) auditEvent(ctx context.Context, a Access, kind ProviderKind, result string) error {
	if err := m.cfg.audit.Append(ctx, Event{At: a.At, Operation: a.Operation, Result: result, Provider: kind, TenantID: a.TenantID, KeyID: a.KeyID, Version: a.Version, Scope: a.Scope, Actor: a.Actor, PolicyEpoch: a.PolicyEpoch}); err != nil {
		return ErrAudit
	}
	return nil
}
