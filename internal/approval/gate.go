// Package approval defines the in-process authorization boundary used by
// control-plane adapters. It intentionally has no network, storage, or clock
// side effects: callers provide the current time for every operation.
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	WarningDelay                = 10 * time.Second
	warningDelay                = WarningDelay
	MaxApprovalTTL              = 30 * time.Minute
	DefaultConfirmationLanguage = "zh-CN"
)

type RiskLevel string

// ApprovalRequest and ConfirmationStatus are stable semantic aliases for
// adapters that prefer domain-oriented names.
type ApprovalRequest = Request
type ConfirmationStatus = Confirmation

const (
	RiskLow       RiskLevel = "low"
	RiskMedium    RiskLevel = "medium"
	RiskHigh      RiskLevel = "high"
	RiskEmergency RiskLevel = "emergency"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRevoked  Status = "revoked"
	StatusExpired  Status = "expired"
)

type ActorRole string

const (
	RoleOperator      ActorRole = "operator"
	RoleSecurityAdmin ActorRole = "security_admin"
	RoleTenantOwner   ActorRole = "tenant_owner"
)

type AuditType string

const (
	AuditSubmitted  AuditType = "submitted"
	AuditAuthorized AuditType = "authorized"
	AuditCheckpoint AuditType = "checkpoint"
	AuditRejected   AuditType = "rejected"
	AuditRevoked    AuditType = "revoked"
	AuditExpired    AuditType = "expired"
)

var (
	ErrInvalidRequest            = errors.New("invalid approval request")
	ErrDuplicateRequest          = errors.New("approval request already exists")
	ErrNotFound                  = errors.New("approval request not found")
	ErrNotPending                = errors.New("approval request is not pending")
	ErrWarningDelay              = errors.New("warning must be read for at least 10 seconds")
	ErrPasswordConfirmation      = errors.New("password confirmation is required")
	ErrSecondConfirmation        = errors.New("second confirmation is required")
	ErrThirdConfirmation         = errors.New("third confirmation is required")
	ErrThirdConfirmationRequired = ErrThirdConfirmation
	ErrConfirmationRequired      = errors.New("interactive confirmation is required")
	ErrLocalConfirmation         = errors.New("interactive confirmation must come from the local control plane")
	ErrConfirmationReplay        = errors.New("confirmation ID has already been used")
	ErrActorRequired             = errors.New("confirmation actor is required")
	ErrInvalidActor              = errors.New("confirmation actor is invalid")
	ErrSessionRequired           = errors.New("confirmation session is required")
	ErrSessionChanged            = errors.New("approval session changed")
	ErrInvalidConfirmationID     = errors.New("confirmation ID is invalid")
	ErrConfirmationLanguage      = errors.New("confirmation language is unsupported")
	ErrConfirmationPhrase        = errors.New("confirmation phrase is invalid")
	ErrIntentChanged             = errors.New("approval intent changed")
	ErrWorkflowChanged           = errors.New("approval workflow changed")
	ErrTTLChanged                = errors.New("approval TTL changed")
	ErrConfirmationSequence      = errors.New("confirmation checkpoints must be completed in order")
	ErrReasonRequired            = errors.New("audit reason is required")
	ErrInvalidReason             = errors.New("audit reason is invalid")
	ErrScopeChanged              = errors.New("approval scope changed")
	ErrEpochChanged              = errors.New("approval policy epoch changed")
	ErrExpired                   = errors.New("approval request expired")
	ErrRevoked                   = errors.New("approval request revoked")
	ErrBreakGlassRequired        = errors.New("restricted break-glass authorization is required")
	ErrBreakGlassReason          = errors.New("break-glass reason is required")
	ErrBreakGlassActor           = errors.New("break-glass requires a security administrator or tenant owner")
	ErrEpochRegression           = errors.New("policy epoch cannot move backwards")
	ErrTTLExceeded               = errors.New("approval TTL exceeds platform limit")
)

// Request is an immutable authorization intent. Sensitive flags are explicit
// so callers cannot accidentally turn a Token/KMS/cluster operation into a
// low-risk pre-approval.
type Request struct {
	ID                   string        `json:"id"`
	Risk                 RiskLevel     `json:"risk"`
	Scope                string        `json:"scope"`
	PolicyEpoch          uint64        `json:"policy_epoch"`
	TTL                  time.Duration `json:"ttl"`
	PreApproved          bool          `json:"pre_approved"`
	Untrusted            bool          `json:"untrusted"`
	Test                 bool          `json:"test"`
	TokenOperation       bool          `json:"token_operation"`
	KMSOperation         bool          `json:"kms_operation"`
	ClusterOperation     bool          `json:"cluster_operation"`
	BreakGlass           bool          `json:"break_glass"`
	Actor                string        `json:"actor"`
	SessionID            string        `json:"session_id"`
	ConfirmationLanguage string        `json:"confirmation_language"`
	IntentDigest         string        `json:"intent_digest"`
	WorkflowDigest       string        `json:"workflow_digest,omitempty"`
	Nonce                string        `json:"nonce"`
}

// Confirmation records the operator's explicit confirmation checkpoints.
// WarningReadAt is checked against the Now value supplied to Confirm; the
// gate never sleeps.
type Confirmation struct {
	WarningReadAt        time.Time     `json:"warning_read_at"`
	PasswordConfirmed    bool          `json:"password_confirmed"`
	SecondConfirmation   bool          `json:"second_confirmation"`
	ThirdConfirmation    bool          `json:"third_confirmation"`
	ConfirmationID       string        `json:"confirmation_id"`
	Actor                string        `json:"actor"`
	ActorRole            ActorRole     `json:"actor_role"`
	Scope                string        `json:"scope"`
	PolicyEpoch          uint64        `json:"policy_epoch"`
	TTL                  time.Duration `json:"ttl"`
	Local                bool          `json:"local"`
	BreakGlass           bool          `json:"break_glass"`
	BreakGlassReason     string        `json:"break_glass_reason,omitempty"`
	SessionID            string        `json:"session_id"`
	ConfirmationLanguage string        `json:"confirmation_language"`
	ConfirmationPhrase   string        `json:"confirmation_phrase"`
	IntentDigest         string        `json:"intent_digest"`
	WorkflowDigest       string        `json:"workflow_digest,omitempty"`
	Nonce                string        `json:"nonce"`
	TOTPConfirmed        bool          `json:"totp_confirmed"`
	ConfirmationStep     uint8         `json:"confirmation_step"`
}

type AuthorizationCommit struct {
	RequestID            string        `json:"request_id"`
	ConfirmationID       string        `json:"confirmation_id"`
	Actor                string        `json:"actor"`
	Scope                string        `json:"scope"`
	PolicyEpoch          uint64        `json:"policy_epoch"`
	Risk                 RiskLevel     `json:"risk"`
	TTL                  time.Duration `json:"ttl"`
	IssuedAt             time.Time     `json:"issued_at"`
	ExpiresAt            time.Time     `json:"expires_at"`
	WorkflowDigest       string        `json:"workflow_digest,omitempty"`
	SessionID            string        `json:"session_id"`
	ConfirmationLanguage string        `json:"confirmation_language"`
	IntentDigest         string        `json:"intent_digest"`
	Nonce                string        `json:"nonce"`
}

type AuditEvent struct {
	Sequence         uint64    `json:"sequence"`
	Type             AuditType `json:"type"`
	At               time.Time `json:"at"`
	RequestID        string    `json:"request_id"`
	Actor            string    `json:"actor"`
	Scope            string    `json:"scope"`
	PolicyEpoch      uint64    `json:"policy_epoch"`
	ConfirmationID   string    `json:"confirmation_id,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	WorkflowDigest   string    `json:"workflow_digest,omitempty"`
	IntentDigest     string    `json:"intent_digest,omitempty"`
	SessionID        string    `json:"session_id,omitempty"`
	ConfirmationStep uint8     `json:"confirmation_step,omitempty"`
	Nonce            string    `json:"nonce,omitempty"`
	PreviousHash     string    `json:"previous_hash,omitempty"`
	Hash             string    `json:"hash,omitempty"`
}

type Record struct {
	ID           string               `json:"id"`
	Request      Request              `json:"request"`
	Status       Status               `json:"status"`
	SubmittedAt  time.Time            `json:"submitted_at"`
	ExpiresAt    time.Time            `json:"expires_at"`
	Confirmation Confirmation         `json:"confirmation"`
	Commit       *AuthorizationCommit `json:"commit,omitempty"`
}

type Gate struct {
	mu                 sync.Mutex
	policyEpoch        uint64
	requests           map[string]Record
	usedIDs            map[string]struct{}
	confirmationOwners map[string]string
	audit              []AuditEvent
	sequence           uint64
	persistence        Persistence
	durableSequences   map[string]uint64
}

func NewGate(policyEpoch uint64) *Gate {
	return &Gate{policyEpoch: policyEpoch, requests: make(map[string]Record), usedIDs: make(map[string]struct{}), confirmationOwners: make(map[string]string), durableSequences: make(map[string]uint64)}
}

// PolicyEpoch returns the fencing generation currently enforced by the gate.
// A nil gate has no valid epoch and therefore reports zero.
func (g *Gate) PolicyEpoch() uint64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.policyEpoch
}

// NewGateWithPersistence binds a durable approval ledger. The persistence is
// optional by design; callers that need durability must opt in explicitly.
func NewGateWithPersistence(policyEpoch uint64, persistence Persistence) (*Gate, error) {
	if persistence == nil || isNilPersistence(persistence) {
		return nil, ErrInvalidPersistence
	}
	g := NewGate(policyEpoch)
	g.persistence = persistence
	return g, nil
}
func isNilPersistence(p Persistence) bool {
	v := reflect.ValueOf(p)
	return v.Kind() == reflect.Ptr && v.IsNil()
}

// BindPersistence binds durability before the gate has accepted any request.
// A bound gate cannot silently switch its source of truth.
func (g *Gate) BindPersistence(p Persistence) error {
	if g == nil {
		return ErrInvalidPersistence
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if p == nil || isNilPersistence(p) {
		return ErrInvalidPersistence
	}
	if g.persistence != nil || len(g.requests) != 0 || len(g.audit) != 0 {
		return ErrBindingConflict
	}
	g.persistence = p
	return nil
}

// RestoreRecord reloads one durable request and its verified event chain.
// Existing in-memory state is never overwritten by a different record.
func (g *Gate) RestoreRecord(ctx context.Context, now time.Time, requestID string) error {
	if g == nil {
		return ErrInvalidPersistence
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.persistence == nil {
		return ErrInvalidPersistence
	}
	if _, ok := g.requests[requestID]; ok {
		return ErrDuplicateRequest
	}
	var record Record
	var events []AuditEvent
	var err error
	if snapshot, ok := g.persistence.(EpochSnapshotPersistence); ok {
		record, events, err = snapshot.LoadWithEventsAtEpoch(ctx, requestID, g.policyEpoch)
	} else {
		if ep, ok := g.persistence.(interface {
			PolicyEpoch(context.Context) (uint64, error)
		}); ok {
			persisted, epochErr := ep.PolicyEpoch(ctx)
			if epochErr != nil || persisted != g.policyEpoch {
				if epochErr != nil {
					return epochErr
				}
				return ErrEpochChanged
			}
		}
		if snapshot, ok := g.persistence.(SnapshotPersistence); ok {
			record, events, err = snapshot.LoadWithEvents(ctx, requestID)
		} else {
			record, err = g.persistence.Load(ctx, requestID)
			if err == nil {
				events, err = g.persistence.Events(ctx, requestID)
			}
		}
	}
	if err != nil {
		return err
	}
	if err := ValidateRecordForAdapter(record); err != nil {
		return err
	}
	if record.Request.PolicyEpoch != g.policyEpoch {
		return ErrEpochChanged
	}
	if len(events) == 0 {
		return ErrInvalidPersistence
	}
	for _, e := range events {
		if e.RequestID != record.ID || e.Scope != record.Request.Scope || e.PolicyEpoch != record.Request.PolicyEpoch || e.IntentDigest != record.Request.IntentDigest || e.SessionID != record.Request.SessionID || e.Nonce != record.Request.Nonce {
			return ErrBindingConflict
		}
	}
	g.requests[record.ID] = cloneRecord(record)
	for _, e := range events {
		g.sequence++
		e.Sequence = g.sequence
		g.audit = append(g.audit, e)
		if e.ConfirmationID != "" {
			if e.Type == AuditAuthorized {
				g.usedIDs[e.ConfirmationID] = struct{}{}
			}
			if e.Type == AuditCheckpoint {
				g.confirmationOwners[e.ConfirmationID] = record.ID
			}
		}
	}
	g.durableSequences[record.ID] = uint64(len(events))
	_ = now // recovery preserves the persisted expiry and never extends TTL
	return nil
}

// Restore loads all IDs supplied by the caller. A ListIDs-capable adapter can
// be used by passing no IDs; adapters without enumeration remain explicit.
func (g *Gate) Restore(ctx context.Context, now time.Time, requestIDs ...string) error {
	if g == nil {
		return ErrInvalidPersistence
	}
	if g.persistence == nil {
		return ErrInvalidPersistence
	}
	if len(requestIDs) == 0 {
		l, ok := g.persistence.(interface {
			ListIDs(context.Context) ([]string, error)
		})
		if !ok {
			return ErrInvalidPersistence
		}
		ids, err := l.ListIDs(ctx)
		if err != nil {
			return err
		}
		requestIDs = ids
	}
	snap := g.snapshot()
	for _, id := range requestIDs {
		if err := g.RestoreRecord(ctx, now, id); err != nil {
			g.mu.Lock()
			g.restore(snap)
			g.mu.Unlock()
			return err
		}
	}
	return nil
}

type gateSnapshot struct {
	requests map[string]Record
	used     map[string]struct{}
	owners   map[string]string
	audit    []AuditEvent
	sequence uint64
	durable  map[string]uint64
}

func (g *Gate) snapshot() gateSnapshot {
	s := gateSnapshot{requests: make(map[string]Record, len(g.requests)), used: make(map[string]struct{}, len(g.usedIDs)), owners: make(map[string]string, len(g.confirmationOwners)), audit: append([]AuditEvent(nil), g.audit...), sequence: g.sequence, durable: make(map[string]uint64, len(g.durableSequences))}
	for k, v := range g.requests {
		s.requests[k] = cloneRecord(v)
	}
	for k := range g.usedIDs {
		s.used[k] = struct{}{}
	}
	for k, v := range g.confirmationOwners {
		s.owners[k] = v
	}
	for k, v := range g.durableSequences {
		s.durable[k] = v
	}
	return s
}
func (g *Gate) restore(s gateSnapshot) {
	g.requests = s.requests
	g.usedIDs = s.used
	g.confirmationOwners = s.owners
	g.audit = s.audit
	g.sequence = s.sequence
	g.durableSequences = s.durable
}

func (g *Gate) persistSince(ctx context.Context, start int, requestID string) error {
	if g.persistence == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	local := g.durableSequences[requestID]
	record := g.requests[requestID]
	batch := make([]ApprovalMutation, 0, 2)
	for _, event := range g.audit[start:] {
		if event.RequestID != requestID {
			continue
		}
		local++
		event.Sequence = local
		key := "gate:" + requestID + ":" + fmt.Sprint(local)
		batch = append(batch, ApprovalMutation{IdempotencyKey: key, WorkflowDigest: record.Request.WorkflowDigest, Record: record, Event: event})
	}
	if len(batch) > 1 {
		if p, ok := g.persistence.(AtomicEpochGuardedPersistence); ok {
			if err := p.ApplyBatchAtEpoch(ctx, g.policyEpoch, batch); err != nil {
				return err
			}
		} else if _, ok := g.persistence.(EpochGuardedPersistence); ok {
			return ErrInvalidPersistence
		} else {
			p, ok := g.persistence.(AtomicPersistence)
			if !ok {
				return ErrInvalidPersistence
			}
			if err := p.ApplyBatch(ctx, batch); err != nil {
				return err
			}
		}
	} else if len(batch) == 1 {
		if p, ok := g.persistence.(EpochGuardedPersistence); ok {
			if err := p.ApplyAtEpoch(ctx, g.policyEpoch, batch[0]); err != nil {
				return err
			}
		} else if p, ok := g.persistence.(AtomicEpochGuardedPersistence); ok {
			if err := p.ApplyBatchAtEpoch(ctx, g.policyEpoch, batch); err != nil {
				return err
			}
		} else if err := g.persistence.Apply(ctx, batch[0]); err != nil {
			return err
		}
	}
	g.durableSequences[requestID] = local
	return nil
}

// NewApprovalGate is the explicit constructor name for control-plane callers.
func NewApprovalGate(policyEpoch uint64) *Gate { return NewGate(policyEpoch) }

func (g *Gate) Submit(now time.Time, req Request) (out Record, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	snap, start := g.snapshot(), len(g.audit)
	defer func() {
		if g.persistence != nil && err == nil {
			if e := g.persistSince(context.Background(), start, req.ID); e != nil {
				g.restore(snap)
				out = Record{}
				err = e
			}
		}
	}()
	if err := normalizeRequest(&req); err != nil {
		return Record{}, err
	}
	if err := validateRequest(req); err != nil {
		return Record{}, err
	}
	if req.PolicyEpoch != g.policyEpoch {
		return Record{}, ErrEpochChanged
	}
	if _, exists := g.requests[req.ID]; exists {
		return Record{}, ErrDuplicateRequest
	}
	record := Record{ID: req.ID, Request: cloneRequest(req), Status: StatusPending, SubmittedAt: now, ExpiresAt: now.Add(req.TTL)}
	if req.PreApproved && req.Risk == RiskLow && !req.sensitive() && !req.BreakGlass {
		id := "preapproved:" + req.ID
		phrase, _ := ExpectedConfirmationPhrase(req.ConfirmationLanguage)
		commit := AuthorizationCommit{RequestID: req.ID, ConfirmationID: id, Actor: req.Actor, Scope: req.Scope, PolicyEpoch: req.PolicyEpoch, Risk: req.Risk, TTL: req.TTL, IssuedAt: now, ExpiresAt: record.ExpiresAt, WorkflowDigest: req.WorkflowDigest, SessionID: req.SessionID, ConfirmationLanguage: req.ConfirmationLanguage, IntentDigest: req.IntentDigest, Nonce: req.Nonce}
		record.Status, record.Commit = StatusApproved, &commit
		record.Confirmation = Confirmation{ConfirmationID: id, Actor: req.Actor, Scope: req.Scope, PolicyEpoch: req.PolicyEpoch, TTL: req.TTL, SessionID: req.SessionID, ConfirmationLanguage: req.ConfirmationLanguage, ConfirmationPhrase: phrase, IntentDigest: req.IntentDigest, WorkflowDigest: req.WorkflowDigest, Nonce: req.Nonce}
	}
	g.requests[req.ID] = record
	g.appendAudit(now, AuditSubmitted, req.ID, req.Actor, req.Scope, req.PolicyEpoch, "", "")
	if record.Status == StatusApproved {
		g.usedIDs[record.Commit.ConfirmationID] = struct{}{}
		g.appendAudit(now, AuditAuthorized, req.ID, req.Actor, req.Scope, req.PolicyEpoch, record.Commit.ConfirmationID, "pre-approved")
	}
	return cloneRecord(record), nil
}

func (g *Gate) Confirm(now time.Time, requestID string, c Confirmation) (out AuthorizationCommit, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	snap, start := g.snapshot(), len(g.audit)
	defer func() {
		if g.persistence != nil {
			if e := g.persistSince(context.Background(), start, requestID); e != nil {
				g.restore(snap)
				out = AuthorizationCommit{}
				err = e
			}
		}
	}()
	record, ok := g.requests[requestID]
	if !ok {
		return AuthorizationCommit{}, ErrNotFound
	}
	reject := func(err error) (AuthorizationCommit, error) {
		g.appendAudit(now, AuditRejected, requestID, c.Actor, record.Request.Scope, record.Request.PolicyEpoch, c.ConfirmationID, err.Error())
		return AuthorizationCommit{}, err
	}
	if record.Status == StatusRevoked {
		return reject(ErrRevoked)
	}
	if record.Status == StatusExpired {
		return reject(ErrExpired)
	}
	if record.Status != StatusPending {
		return reject(ErrNotPending)
	}
	if !now.Before(record.ExpiresAt) {
		record.Status = StatusExpired
		g.requests[requestID] = record
		g.appendAudit(now, AuditExpired, requestID, c.Actor, record.Request.Scope, record.Request.PolicyEpoch, c.ConfirmationID, "TTL elapsed")
		return AuthorizationCommit{}, ErrExpired
	}
	if record.Request.PolicyEpoch != g.policyEpoch || c.PolicyEpoch != record.Request.PolicyEpoch {
		return reject(ErrEpochChanged)
	}
	if c.Scope != record.Request.Scope {
		return reject(ErrScopeChanged)
	}
	if c.Actor == "" {
		return reject(ErrActorRequired)
	}
	if err := validateOpaque(c.Actor, false); err != nil {
		return reject(ErrInvalidActor)
	}
	if c.ConfirmationID == "" {
		return reject(ErrConfirmationRequired)
	}
	if err := validateOpaque(c.ConfirmationID, false); err != nil {
		return reject(ErrInvalidConfirmationID)
	}
	if _, used := g.usedIDs[c.ConfirmationID]; used {
		return reject(ErrConfirmationReplay)
	}
	if owner, reserved := g.confirmationOwners[c.ConfirmationID]; reserved && owner != requestID {
		return reject(ErrConfirmationReplay)
	}
	if !c.Local {
		return reject(ErrLocalConfirmation)
	}
	if c.SessionID == "" {
		return reject(ErrSessionRequired)
	}
	if err := validateOpaque(c.SessionID, false); err != nil {
		return reject(ErrSessionRequired)
	}
	if record.Request.SessionID != "" && c.SessionID != record.Request.SessionID {
		return reject(ErrSessionChanged)
	}
	if c.ConfirmationLanguage == "" {
		return reject(ErrConfirmationLanguage)
	}
	language, err := NormalizeConfirmationLanguage(c.ConfirmationLanguage)
	if err != nil || language != record.Request.ConfirmationLanguage {
		return reject(ErrConfirmationLanguage)
	}
	c.ConfirmationLanguage = language
	expectedPhrase, _ := ExpectedConfirmationPhrase(language)
	if c.ConfirmationPhrase != expectedPhrase {
		return reject(ErrConfirmationPhrase)
	}
	if c.IntentDigest != record.Request.IntentDigest {
		return reject(ErrIntentChanged)
	}
	if c.WorkflowDigest != record.Request.WorkflowDigest {
		return reject(ErrWorkflowChanged)
	}
	if c.Nonce == "" || c.Nonce != record.Request.Nonce {
		return reject(ErrIntentChanged)
	}
	if c.TTL != 0 && c.TTL != record.Request.TTL {
		return reject(ErrTTLChanged)
	}
	if c.WarningReadAt.IsZero() || c.WarningReadAt.After(now) || now.Sub(c.WarningReadAt) < warningDelay {
		return reject(ErrWarningDelay)
	}
	if !c.PasswordConfirmed && !c.TOTPConfirmed {
		return reject(ErrPasswordConfirmation)
	}
	if !c.SecondConfirmation {
		return reject(ErrSecondConfirmation)
	}
	if record.Request.Risk == RiskEmergency {
		if !record.Request.BreakGlass || !c.BreakGlass {
			return reject(ErrBreakGlassRequired)
		}
		if strings.TrimSpace(c.BreakGlassReason) == "" {
			return reject(ErrBreakGlassReason)
		}
		if err := validateReason(c.BreakGlassReason); err != nil {
			return reject(ErrInvalidReason)
		}
		if c.ActorRole != RoleSecurityAdmin && c.ActorRole != RoleTenantOwner {
			return reject(ErrBreakGlassActor)
		}
	}
	if record.Request.requiresThirdConfirmation() {
		if !c.ThirdConfirmation {
			if record.Confirmation.ConfirmationID != "" {
				if err := sameCheckpoint(record.Confirmation, c); err != nil {
					return reject(err)
				}
			} else {
				c.TTL = record.Request.TTL
				c.ConfirmationStep = 2
				record.Confirmation = c
				g.requests[requestID] = record
				g.confirmationOwners[c.ConfirmationID] = requestID
			}
			g.appendAudit(now, AuditCheckpoint, requestID, c.Actor, c.Scope, c.PolicyEpoch, c.ConfirmationID, "second confirmation recorded; third confirmation required")
			return AuthorizationCommit{}, ErrThirdConfirmation
		}
		if record.Confirmation.ConfirmationID == "" || record.Confirmation.ConfirmationStep < 2 {
			return reject(ErrConfirmationSequence)
		}
		if err := sameCheckpoint(record.Confirmation, c); err != nil {
			return reject(err)
		}
		c.ConfirmationStep = 3
	} else {
		c.ConfirmationStep = 2
	}
	c.TTL = record.Request.TTL
	commit := AuthorizationCommit{RequestID: requestID, ConfirmationID: c.ConfirmationID, Actor: c.Actor, Scope: c.Scope, PolicyEpoch: c.PolicyEpoch, Risk: record.Request.Risk, TTL: record.Request.TTL, IssuedAt: now, ExpiresAt: record.ExpiresAt, WorkflowDigest: record.Request.WorkflowDigest, SessionID: c.SessionID, ConfirmationLanguage: c.ConfirmationLanguage, IntentDigest: c.IntentDigest, Nonce: record.Request.Nonce}
	record.Status, record.Confirmation, record.Commit = StatusApproved, c, &commit
	g.requests[requestID] = record
	g.usedIDs[c.ConfirmationID] = struct{}{}
	g.appendAudit(now, AuditAuthorized, requestID, c.Actor, c.Scope, c.PolicyEpoch, c.ConfirmationID, "interactive confirmation")
	return commit, nil
}

func (g *Gate) Revoke(now time.Time, requestID, actor, reason string) (err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	snap, start := g.snapshot(), len(g.audit)
	defer func() {
		if g.persistence != nil && err == nil {
			if e := g.persistSince(context.Background(), start, requestID); e != nil {
				g.restore(snap)
				err = e
			}
		}
	}()
	record, ok := g.requests[requestID]
	if !ok {
		return ErrNotFound
	}
	if record.Status == StatusRevoked {
		return ErrRevoked
	}
	if actor == "" {
		return ErrActorRequired
	}
	if err := validateOpaque(actor, false); err != nil {
		return ErrInvalidActor
	}
	if strings.TrimSpace(reason) == "" {
		return ErrReasonRequired
	}
	if err := validateReason(reason); err != nil {
		return ErrInvalidReason
	}
	record.Status, record.Commit = StatusRevoked, nil
	g.requests[requestID] = record
	g.appendAudit(now, AuditRevoked, requestID, actor, record.Request.Scope, record.Request.PolicyEpoch, "", reason)
	return nil
}

func (g *Gate) AdvanceEpoch(epoch uint64) error {
	if g == nil {
		return ErrInvalidPersistence
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if epoch < g.policyEpoch {
		return ErrEpochRegression
	}
	if g.persistence != nil {
		cp, ok := g.persistence.(interface {
			CompareAndSetEpoch(context.Context, uint64, uint64) error
		})
		if !ok {
			return ErrInvalidPersistence
		}
		if err := cp.CompareAndSetEpoch(context.Background(), g.policyEpoch, epoch); err != nil {
			return err
		}
	}
	g.policyEpoch = epoch
	return nil
}

func (g *Gate) AuditEvents() []AuditEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEvent, len(g.audit))
	copy(out, g.audit)
	return out
}

func (g *Gate) Get(requestID string) (Record, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	record, ok := g.requests[requestID]
	if !ok {
		return Record{}, false
	}
	return cloneRecord(record), true
}

func (g *Gate) appendAudit(now time.Time, typ AuditType, requestID, actor, scope string, epoch uint64, confirmationID, reason string) {
	g.sequence++
	event := AuditEvent{Sequence: g.sequence, Type: typ, At: now, RequestID: requestID, Actor: actor, Scope: scope, PolicyEpoch: epoch, ConfirmationID: confirmationID, Reason: reason}
	if record, ok := g.requests[requestID]; ok {
		event.WorkflowDigest = record.Request.WorkflowDigest
		event.IntentDigest = record.Request.IntentDigest
		event.SessionID = record.Request.SessionID
		event.ConfirmationStep = record.Confirmation.ConfirmationStep
		event.Nonce = record.Request.Nonce
	}
	g.audit = append(g.audit, event)
}

func (r Request) sensitive() bool {
	return r.Untrusted || r.Test || r.TokenOperation || r.KMSOperation || r.ClusterOperation || r.Risk == RiskHigh || r.Risk == RiskEmergency
}
func (r Request) requiresThirdConfirmation() bool { return r.sensitive() }

// NormalizeConfirmationLanguage accepts only the language tags for which the
// control plane has a deterministic confirmation phrase. It deliberately
// rejects whitespace instead of trimming it so a UI cannot silently switch
// the language bound to an approval.
func NormalizeConfirmationLanguage(value string) (string, error) {
	if value == "" {
		return DefaultConfirmationLanguage, nil
	}
	if err := validateOpaque(value, false); err != nil {
		return "", ErrConfirmationLanguage
	}
	switch strings.ToLower(value) {
	case "zh", "zh-cn", "zh-hans":
		return "zh-CN", nil
	case "zh-tw", "zh-hk", "zh-hant":
		return "zh-TW", nil
	case "en", "en-us", "en-gb":
		return "en-US", nil
	default:
		return "", ErrConfirmationLanguage
	}
}

// ExpectedConfirmationPhrase returns the exact phrase an operator must type
// for the selected UI language. The phrase is intentionally short, stable,
// and compared byte-for-byte by Confirm.
func ExpectedConfirmationPhrase(language string) (string, error) {
	canonical, err := NormalizeConfirmationLanguage(language)
	if err != nil {
		return "", err
	}
	switch canonical {
	case "zh-CN":
		return "确认", nil
	case "zh-TW":
		return "確認", nil
	case "en-US":
		return "CONFIRM", nil
	default:
		return "", ErrConfirmationLanguage
	}
}

// IntentDigestForRequest computes the immutable operation binding used by the
// gate. Actor/session and presentation language are intentionally excluded so
// an authorized delegate can confirm the same operation without changing its
// security-relevant scope. Callers should set Request.IntentDigest when they
// have a richer operation payload; Submit fills it from this canonical
// request shape when omitted.
func IntentDigestForRequest(r Request) string {
	type intent struct {
		ID               string    `json:"id"`
		Risk             RiskLevel `json:"risk"`
		Scope            string    `json:"scope"`
		PolicyEpoch      uint64    `json:"policy_epoch"`
		TTL              int64     `json:"ttl_ns"`
		PreApproved      bool      `json:"pre_approved"`
		Untrusted        bool      `json:"untrusted"`
		Test             bool      `json:"test"`
		TokenOperation   bool      `json:"token_operation"`
		KMSOperation     bool      `json:"kms_operation"`
		ClusterOperation bool      `json:"cluster_operation"`
		BreakGlass       bool      `json:"break_glass"`
		WorkflowDigest   string    `json:"workflow_digest,omitempty"`
	}
	b, _ := json.Marshal(intent{ID: r.ID, Risk: r.Risk, Scope: r.Scope, PolicyEpoch: r.PolicyEpoch, TTL: int64(r.TTL), PreApproved: r.PreApproved, Untrusted: r.Untrusted, Test: r.Test, TokenOperation: r.TokenOperation, KMSOperation: r.KMSOperation, ClusterOperation: r.ClusterOperation, BreakGlass: r.BreakGlass, WorkflowDigest: r.WorkflowDigest})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeRequest(r *Request) error {
	if r == nil {
		return ErrInvalidRequest
	}
	if err := validateOpaque(r.ID, true); err != nil {
		return ErrInvalidRequest
	}
	if err := validateOpaque(r.Scope, true); err != nil {
		return ErrInvalidRequest
	}
	if err := validateOpaque(r.Actor, true); err != nil {
		return ErrInvalidRequest
	}
	if r.SessionID != "" {
		if err := validateOpaque(r.SessionID, false); err != nil {
			return ErrInvalidRequest
		}
	}
	if r.SessionID == "" {
		return ErrInvalidRequest
	}
	if r.ConfirmationLanguage == "" {
		return ErrInvalidRequest
	}
	language, err := NormalizeConfirmationLanguage(r.ConfirmationLanguage)
	if err != nil {
		return ErrInvalidRequest
	}
	r.ConfirmationLanguage = language
	if r.WorkflowDigest != "" && validateOpaque(r.WorkflowDigest, false) != nil {
		return ErrInvalidRequest
	}
	if r.Nonce == "" {
		r.Nonce = nonceForRequest(*r)
	} else if validateOpaque(r.Nonce, false) != nil {
		return ErrInvalidRequest
	}
	if r.IntentDigest == "" {
		r.IntentDigest = IntentDigestForRequest(*r)
	} else if !validDigest(r.IntentDigest) {
		return ErrInvalidRequest
	}
	return nil
}

func validateRequest(r Request) error {
	if r.ID == "" || r.Scope == "" || r.TTL <= 0 || r.Actor == "" || r.SessionID == "" || r.ConfirmationLanguage == "" || !validDigest(r.IntentDigest) || r.Nonce == "" {
		return ErrInvalidRequest
	}
	if validateOpaque(r.ID, true) != nil || validateOpaque(r.Scope, true) != nil || validateOpaque(r.Actor, true) != nil || validateOpaque(r.SessionID, true) != nil || validateOpaque(r.Nonce, true) != nil {
		return ErrInvalidRequest
	}
	if language, err := NormalizeConfirmationLanguage(r.ConfirmationLanguage); err != nil || language != r.ConfirmationLanguage {
		return ErrInvalidRequest
	}
	if r.WorkflowDigest != "" && validateOpaque(r.WorkflowDigest, false) != nil {
		return ErrInvalidRequest
	}
	if r.TTL > MaxApprovalTTL {
		return ErrTTLExceeded
	}
	switch r.Risk {
	case RiskLow, RiskMedium, RiskHigh, RiskEmergency:
	default:
		return ErrInvalidRequest
	}
	if r.Risk == RiskEmergency && !r.BreakGlass {
		return ErrBreakGlassRequired
	}
	return nil
}

func validateOpaque(value string, required bool) error {
	if required && value == "" {
		return ErrInvalidRequest
	}
	if !utf8.ValidString(value) {
		return ErrInvalidRequest
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ErrInvalidRequest
		}
	}
	return nil
}

// ValidateIdentifier exposes the same no-whitespace, no-control-character
// rule to persistence adapters. Adapters must reject invalid identifiers;
// they must not trim or otherwise rewrite them before lookup.
func ValidateIdentifier(value string) error { return validateOpaque(value, true) }

// ValidateRecordForAdapter verifies a record loaded from durable storage before
// it is exposed to a caller. This is intentionally separate from Gate state
// mutation so adapters cannot accidentally treat malformed persisted data as
// an authorization.
func ValidateRecordForAdapter(record Record) error {
	if ValidateIdentifier(record.ID) != nil || record.Request.ID != record.ID {
		return ErrInvalidRequest
	}
	if err := validateRequest(record.Request); err != nil {
		return err
	}
	if record.SubmittedAt.IsZero() || record.ExpiresAt.IsZero() || record.ExpiresAt.Before(record.SubmittedAt) || !record.ExpiresAt.Equal(record.SubmittedAt.Add(record.Request.TTL)) {
		return ErrInvalidRequest
	}
	switch record.Status {
	case StatusPending, StatusApproved, StatusRevoked, StatusExpired:
	default:
		return ErrInvalidRequest
	}
	if record.Status == StatusApproved && record.Commit == nil {
		return ErrInvalidRequest
	}
	if record.Commit != nil {
		if record.Status != StatusApproved || record.Commit.RequestID != record.ID || ValidateIdentifier(record.Commit.ConfirmationID) != nil || ValidateIdentifier(record.Commit.Actor) != nil || record.Commit.Scope != record.Request.Scope || record.Commit.PolicyEpoch != record.Request.PolicyEpoch || record.Commit.IntentDigest != record.Request.IntentDigest || record.Commit.WorkflowDigest != record.Request.WorkflowDigest || record.Commit.SessionID != record.Request.SessionID || record.Commit.Nonce != record.Request.Nonce || !record.Commit.ExpiresAt.Equal(record.ExpiresAt) || record.Commit.IssuedAt.IsZero() || record.Commit.IssuedAt.Before(record.SubmittedAt) || record.Commit.IssuedAt.After(record.ExpiresAt) {
			return ErrInvalidRequest
		}
	}
	if record.Confirmation.ConfirmationID != "" {
		confirmation := record.Confirmation
		if record.Status != StatusPending && record.Status != StatusApproved {
			return ErrInvalidRequest
		}
		interactive := !record.Request.PreApproved
		if ValidateIdentifier(confirmation.ConfirmationID) != nil || ValidateIdentifier(confirmation.Actor) != nil || ValidateIdentifier(confirmation.SessionID) != nil || confirmation.Scope != record.Request.Scope || confirmation.PolicyEpoch != record.Request.PolicyEpoch || confirmation.IntentDigest != record.Request.IntentDigest || confirmation.WorkflowDigest != record.Request.WorkflowDigest || confirmation.Nonce != record.Request.Nonce || confirmation.ConfirmationLanguage != record.Request.ConfirmationLanguage || confirmation.ConfirmationPhrase == "" || confirmation.TTL != record.Request.TTL || (record.Status == StatusApproved && record.Commit != nil && confirmation.ConfirmationID != record.Commit.ConfirmationID) || (interactive && (confirmation.WarningReadAt.IsZero() || !confirmation.SecondConfirmation || (!confirmation.PasswordConfirmed && !confirmation.TOTPConfirmed) || confirmation.ConfirmationStep < 2 || confirmation.ConfirmationStep > 3 || (record.Request.requiresThirdConfirmation() && confirmation.ConfirmationStep == 3 && !confirmation.ThirdConfirmation))) {
			return ErrInvalidRequest
		}
		phrase, err := ExpectedConfirmationPhrase(confirmation.ConfirmationLanguage)
		if err != nil || confirmation.ConfirmationPhrase != phrase {
			return ErrInvalidRequest
		}
	}
	return nil
}

func validateReason(value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalidReason
	}
	if len([]rune(value)) > 2048 {
		return ErrInvalidReason
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ErrInvalidReason
		}
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}
	return value == strings.ToLower(value)
}

func nonceForRequest(r Request) string {
	b := []byte("cheesewaf approval nonce\x00" + r.ID + "\x00" + r.Scope + "\x00" + string(r.Risk) + "\x00" + r.Actor)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sameCheckpoint(previous, current Confirmation) error {
	if previous.ConfirmationID != current.ConfirmationID {
		return ErrConfirmationReplay
	}
	if previous.Scope != current.Scope {
		return ErrScopeChanged
	}
	if previous.IntentDigest != current.IntentDigest {
		return ErrIntentChanged
	}
	if previous.Nonce != current.Nonce {
		return ErrIntentChanged
	}
	if previous.PolicyEpoch != current.PolicyEpoch {
		return ErrEpochChanged
	}
	if previous.SessionID != current.SessionID {
		return ErrSessionChanged
	}
	if previous.ConfirmationLanguage != current.ConfirmationLanguage || previous.ConfirmationPhrase != current.ConfirmationPhrase {
		return ErrConfirmationLanguage
	}
	if previous.WarningReadAt.IsZero() || !previous.WarningReadAt.Equal(current.WarningReadAt) {
		return ErrConfirmationSequence
	}
	if previous.Actor != current.Actor || previous.ActorRole != current.ActorRole || previous.Local != current.Local || previous.BreakGlass != current.BreakGlass || previous.BreakGlassReason != current.BreakGlassReason || previous.PasswordConfirmed != current.PasswordConfirmed || previous.TOTPConfirmed != current.TOTPConfirmed || previous.SecondConfirmation != current.SecondConfirmation {
		return ErrConfirmationSequence
	}
	return nil
}

func cloneRequest(r Request) Request { return r }
func cloneRecord(r Record) Record {
	if r.Commit != nil {
		c := *r.Commit
		r.Commit = &c
	}
	return r
}
