package netlease

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrTemporarySessionUnavailable = errors.New("temporary session is unavailable")
	ErrTemporarySessionExpired     = errors.New("temporary session expired")
	ErrTemporarySessionRevoked     = errors.New("temporary session revoked")
	ErrTemporarySessionTTL         = errors.New("temporary session TTL exceeds platform limit")
	ErrAdministratorSessionDenied  = errors.New("administrator session is not valid")
	ErrAdministratorPasswordDenied = errors.New("administrator password confirmation was rejected")
	ErrConfirmationScope           = errors.New("confirmation scope mismatch")
)

// AdministratorIdentity is the authenticated management-plane identity that
// owns a temporary egress session. ManagementSessionID is optional only for
// explicit local adapters; remote control-plane adapters must require it.
type AdministratorIdentity struct {
	ID                  string
	ManagementSessionID string
}

func (i AdministratorIdentity) valid() bool {
	return validOpaque(i.ID, 256) && (i.ManagementSessionID == "" || validOpaque(i.ManagementSessionID, 256))
}

// AdministratorAuthenticator keeps user/session/password verification outside
// the lease package. Passwords are passed only for comparison and are never
// persisted in TemporarySession or TemporaryConfirmation.
type AdministratorAuthenticator interface {
	VerifySession(context.Context, AdministratorIdentity, time.Time) error
	VerifyPassword(context.Context, AdministratorIdentity, string) error
}

type TemporarySession struct {
	ID, AdministratorID, ManagementSessionID string
	IssuedAt, ExpiresAt                      time.Time
	Revoked                                  bool
}

type BeginTemporarySessionRequest struct {
	Identity AdministratorIdentity
	TTL      time.Duration
}

// ConfirmationInput is the complete capability request approved by an
// administrator password prompt. It has no caller-provided ConfirmationID or
// OperatorID: both are generated/bound by the temporary session manager.
type ConfirmationInput struct {
	SessionID, Password     string
	PluginID, PluginVersion string
	Target                  Target
	TLSFingerprint          string
	PolicyEpoch             uint64
	TTL                     time.Duration
	MaxBytes                int64
}

type TemporaryConfirmation struct {
	ID, SessionID, AdministratorID string
	PluginID, PluginVersion        string
	Target                         Target
	TLSFingerprint                 string
	PolicyEpoch                    uint64
	TTL                            time.Duration
	MaxBytes                       int64
	IssuedAt, ExpiresAt            time.Time
	Used                           bool
}

type TemporarySessionManagerOptions struct {
	Now           func() time.Time
	Authenticator AdministratorAuthenticator
	MaxTTL        time.Duration
}

type temporaryConfirmationRecord struct {
	confirmation TemporaryConfirmation
	identity     AdministratorIdentity
}

// TemporarySessionManager creates short-lived local capabilities on top of an
// already authenticated administrator session. It is intentionally in-memory:
// process restart revokes every temporary session and confirmation.
type TemporarySessionManager struct {
	mu            sync.Mutex
	now           func() time.Time
	authenticator AdministratorAuthenticator
	maxTTL        time.Duration
	sessions      map[string]TemporarySession
	confirmations map[string]temporaryConfirmationRecord
}

func NewTemporarySessionManager(opts TemporarySessionManagerOptions) (*TemporarySessionManager, error) {
	if opts.Authenticator == nil {
		return nil, ErrTemporarySessionUnavailable
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = MaxLeaseTTL
	}
	if opts.MaxTTL > MaxLeaseTTL {
		opts.MaxTTL = MaxLeaseTTL
	}
	return &TemporarySessionManager{
		now:           opts.Now,
		authenticator: opts.Authenticator,
		maxTTL:        opts.MaxTTL,
		sessions:      make(map[string]TemporarySession),
		confirmations: make(map[string]temporaryConfirmationRecord),
	}, nil
}

// Begin validates the current administrator session before minting a new
// temporary session. A password is deliberately not accepted here; the actual
// capability is minted only by Confirm, which requires a fresh password check.
func (m *TemporarySessionManager) Begin(ctx context.Context, req BeginTemporarySessionRequest) (TemporarySession, error) {
	if m == nil || !req.Identity.valid() || req.TTL <= 0 {
		return TemporarySession{}, ErrTemporarySessionUnavailable
	}
	if req.TTL > m.maxTTL {
		return TemporarySession{}, ErrTemporarySessionTTL
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := m.now().UTC()
	if err := m.authenticator.VerifySession(ctx, req.Identity, now); err != nil {
		return TemporarySession{}, wrapAdministratorSessionError(err)
	}
	id, err := newID()
	if err != nil {
		return TemporarySession{}, err
	}
	session := TemporarySession{
		ID:                  id,
		AdministratorID:     req.Identity.ID,
		ManagementSessionID: req.Identity.ManagementSessionID,
		IssuedAt:            now,
		ExpiresAt:           now.Add(req.TTL),
	}
	m.mu.Lock()
	m.sessions[session.ID] = session
	m.mu.Unlock()
	return session, nil
}

// Confirm rechecks the management session and administrator password before
// producing a one-time confirmation bound to every socket-lease field.
func (m *TemporarySessionManager) Confirm(ctx context.Context, input ConfirmationInput) (TemporaryConfirmation, error) {
	if m == nil || !validConfirmationInput(input) {
		return TemporaryConfirmation{}, ErrInvalidLease
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := m.now().UTC()
	m.mu.Lock()
	session, err := m.activeSessionLocked(input.SessionID, now)
	m.mu.Unlock()
	if err != nil {
		return TemporaryConfirmation{}, err
	}
	identity := AdministratorIdentity{ID: session.AdministratorID, ManagementSessionID: session.ManagementSessionID}
	if err := m.authenticator.VerifySession(ctx, identity, now); err != nil {
		return TemporaryConfirmation{}, wrapAdministratorSessionError(err)
	}
	if err := m.authenticator.VerifyPassword(ctx, identity, input.Password); err != nil {
		return TemporaryConfirmation{}, wrapAdministratorPasswordError(err)
	}
	id, err := newID()
	if err != nil {
		return TemporaryConfirmation{}, err
	}
	expiresAt := now.Add(input.TTL)
	if session.ExpiresAt.Before(expiresAt) {
		expiresAt = session.ExpiresAt
	}
	confirmation := TemporaryConfirmation{
		ID:              id,
		SessionID:       session.ID,
		AdministratorID: session.AdministratorID,
		PluginID:        input.PluginID,
		PluginVersion:   input.PluginVersion,
		Target:          input.Target,
		TLSFingerprint:  input.TLSFingerprint,
		PolicyEpoch:     input.PolicyEpoch,
		TTL:             input.TTL,
		MaxBytes:        input.MaxBytes,
		IssuedAt:        now,
		ExpiresAt:       expiresAt,
	}
	m.mu.Lock()
	if _, err := m.activeSessionLocked(input.SessionID, now); err != nil {
		m.mu.Unlock()
		return TemporaryConfirmation{}, err
	}
	m.confirmations[id] = temporaryConfirmationRecord{confirmation: confirmation, identity: identity}
	m.mu.Unlock()
	return confirmation, nil
}

// ConfirmationVerifier returns the verifier required by NewSecureManager.
// The verifier consumes the confirmation before the lease is issued. If a
// concurrent policy update subsequently rejects issuance, the confirmation
// remains spent, which is safer than allowing a replay under a changed policy.
func (m *TemporarySessionManager) ConfirmationVerifier() ConfirmationVerifier {
	return func(req ConfirmationRequest) error {
		return m.ConsumeConfirmation(context.Background(), req)
	}
}

// ConsumeConfirmation atomically validates the exact lease binding, verifies
// that the backing administrator session is still active, and marks the ID
// used. It is safe for concurrent IssueTemporary calls.
func (m *TemporarySessionManager) ConsumeConfirmation(ctx context.Context, req ConfirmationRequest) error {
	if m == nil || !validConfirmationRequest(req) {
		return ErrConfirmationRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := m.now().UTC()
	m.mu.Lock()
	record, ok := m.confirmations[req.ID]
	if !ok {
		m.mu.Unlock()
		return ErrConfirmationRequired
	}
	if record.confirmation.Used {
		m.mu.Unlock()
		return ErrConfirmationReplay
	}
	if !now.Before(record.confirmation.ExpiresAt) {
		m.mu.Unlock()
		return ErrConfirmationExpired
	}
	if !confirmationMatches(record.confirmation, req) {
		m.mu.Unlock()
		return ErrConfirmationScope
	}
	if _, err := m.activeSessionLocked(record.confirmation.SessionID, now); err != nil {
		m.mu.Unlock()
		return err
	}
	identity := record.identity
	m.mu.Unlock()
	if err := m.authenticator.VerifySession(ctx, identity, now); err != nil {
		return wrapAdministratorSessionError(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok = m.confirmations[req.ID]
	if !ok {
		return ErrConfirmationRequired
	}
	if record.confirmation.Used {
		return ErrConfirmationReplay
	}
	if !now.Before(record.confirmation.ExpiresAt) {
		return ErrConfirmationExpired
	}
	if !confirmationMatches(record.confirmation, req) {
		return ErrConfirmationScope
	}
	if _, err := m.activeSessionLocked(record.confirmation.SessionID, now); err != nil {
		return err
	}
	record.confirmation.Used = true
	m.confirmations[req.ID] = record
	return nil
}

func (m *TemporarySessionManager) Revoke(id string) error {
	if m == nil || !validOpaque(id, 256) {
		return ErrTemporarySessionUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	if !ok {
		return ErrTemporarySessionUnavailable
	}
	session.Revoked = true
	m.sessions[id] = session
	return nil
}

func (m *TemporarySessionManager) Get(id string) (TemporarySession, bool) {
	if m == nil {
		return TemporarySession{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[id]
	return session, ok
}

func (m *TemporarySessionManager) Confirmation(id string) (TemporaryConfirmation, bool) {
	if m == nil {
		return TemporaryConfirmation{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.confirmations[id]
	return record.confirmation, ok
}

func (m *TemporarySessionManager) activeSessionLocked(id string, now time.Time) (TemporarySession, error) {
	session, ok := m.sessions[id]
	if !ok {
		return TemporarySession{}, ErrTemporarySessionUnavailable
	}
	if session.Revoked {
		return TemporarySession{}, ErrTemporarySessionRevoked
	}
	if !now.Before(session.ExpiresAt) {
		return TemporarySession{}, ErrTemporarySessionExpired
	}
	return session, nil
}

func validConfirmationInput(input ConfirmationInput) bool {
	return validOpaque(input.SessionID, 256) &&
		input.Password != "" &&
		validOpaque(input.PluginID, 256) &&
		validOpaque(input.PluginVersion, 128) &&
		input.Target.Validate() == nil &&
		ValidateTLSFingerprint(input.TLSFingerprint) == nil &&
		input.PolicyEpoch != 0 &&
		input.TTL > 0 && input.TTL <= MaxLeaseTTL &&
		input.MaxBytes >= 0
}

func validConfirmationRequest(req ConfirmationRequest) bool {
	return validOpaque(req.ID, 256) &&
		validOpaque(req.OperatorID, 256) &&
		validOpaque(req.PluginID, 256) &&
		validOpaque(req.PluginVersion, 128) &&
		req.Target.Validate() == nil &&
		ValidateTLSFingerprint(req.TLSFingerprint) == nil &&
		req.PolicyEpoch != 0 &&
		req.TTL > 0 && req.TTL <= MaxLeaseTTL &&
		req.TemporaryEgress &&
		req.ResourceID == "" &&
		req.MaxBytes >= 0
}

func confirmationMatches(confirmation TemporaryConfirmation, req ConfirmationRequest) bool {
	return confirmation.ID == req.ID &&
		confirmation.AdministratorID == req.OperatorID &&
		confirmation.PluginID == req.PluginID &&
		confirmation.PluginVersion == req.PluginVersion &&
		confirmation.Target.equal(req.Target) &&
		confirmation.TLSFingerprint == req.TLSFingerprint &&
		confirmation.PolicyEpoch == req.PolicyEpoch &&
		confirmation.TTL == req.TTL &&
		confirmation.MaxBytes == req.MaxBytes &&
		!req.ConfirmationExpiresAt.IsZero() &&
		confirmation.ExpiresAt.Equal(req.ConfirmationExpiresAt) &&
		req.TemporaryEgress && req.ResourceID == ""
}

func wrapAdministratorSessionError(err error) error {
	if err == nil {
		return nil
	}
	return ErrAdministratorSessionDenied
}

func wrapAdministratorPasswordError(err error) error {
	if err == nil {
		return nil
	}
	return ErrAdministratorPasswordDenied
}
