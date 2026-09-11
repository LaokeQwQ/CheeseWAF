package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

var (
	ErrInvalidPersistence  = errors.New("invalid approval persistence mutation")
	ErrIdempotencyConflict = errors.New("approval persistence idempotency conflict")
	ErrEventSequence       = errors.New("approval event sequence conflict")
	ErrBindingConflict     = errors.New("approval persistence binding conflict")
	ErrApprovalNotFound    = errors.New("persisted approval not found")
	ErrPersistenceNotFound = ErrApprovalNotFound
)

type ApprovalMutation struct {
	IdempotencyKey string
	WorkflowDigest string
	Record         Record
	Event          AuditEvent
}
type Persistence interface {
	Apply(context.Context, ApprovalMutation) error
	Load(context.Context, string) (Record, error)
	Events(context.Context, string) ([]AuditEvent, error)
}

// SnapshotPersistence loads a record and its event chain from one consistent
// persistence snapshot. Persistence implementations may expose this optional
// capability when separate Load and Events calls could observe different
// commits during recovery.
type SnapshotPersistence interface {
	Persistence
	LoadWithEvents(context.Context, string) (Record, []AuditEvent, error)
}

// EpochSnapshotPersistence loads a record and its event chain while checking
// the policy epoch in the same persistence snapshot. This is an optional
// stronger capability for recovery paths that must bind all three reads.
type EpochSnapshotPersistence interface {
	Persistence
	LoadWithEventsAtEpoch(context.Context, string, uint64) (Record, []AuditEvent, error)
}

// AtomicPersistence applies a logical mutation batch as one durable unit.
type AtomicPersistence interface {
	Persistence
	ApplyBatch(context.Context, []ApprovalMutation) error
}

// EpochGuardedPersistence applies one mutation only when the durable policy
// epoch still matches the caller's expected epoch. It is optional so legacy
// adapters can retain the original Persistence contract while stronger
// adapters fence writes against an externally advanced policy.
type EpochGuardedPersistence interface {
	Persistence
	ApplyAtEpoch(context.Context, uint64, ApprovalMutation) error
}

// AtomicEpochGuardedPersistence applies a logical mutation batch atomically
// only when the durable policy epoch still matches the caller's expected
// epoch.
type AtomicEpochGuardedPersistence interface {
	Persistence
	ApplyBatchAtEpoch(context.Context, uint64, []ApprovalMutation) error
}
type approvalMemoryRecord struct {
	record   Record
	workflow string
	events   []AuditEvent
}
type MemoryPersistence struct {
	mu          sync.RWMutex
	records     map[string]approvalMemoryRecord
	idempotency map[string]string
}

var _ SnapshotPersistence = (*MemoryPersistence)(nil)
var _ EpochSnapshotPersistence = (*MemoryPersistence)(nil)

func NewMemoryPersistence() *MemoryPersistence {
	return &MemoryPersistence{records: make(map[string]approvalMemoryRecord), idempotency: make(map[string]string)}
}
func (p *MemoryPersistence) Apply(ctx context.Context, m ApprovalMutation) error {
	if p == nil || ctx == nil {
		return ErrInvalidPersistence
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.applyLocked(ctx, m)
}
func (p *MemoryPersistence) applyLocked(ctx context.Context, m ApprovalMutation) error {
	if p == nil || ctx == nil {
		return ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateMutation(m); err != nil {
		return err
	}
	if m.Event.WorkflowDigest != "" && m.Event.WorkflowDigest != m.WorkflowDigest {
		return ErrBindingConflict
	}
	m.Event.WorkflowDigest = m.WorkflowDigest
	m.Event.IntentDigest = m.Record.Request.IntentDigest
	m.Event.SessionID = m.Record.Request.SessionID
	m.Event.Nonce = m.Record.Request.Nonce
	key := m.Record.ID
	idem := m.IdempotencyKey
	fp := mutationFingerprint(m)
	if prior, ok := p.idempotency[idem]; ok {
		if prior == fp {
			return nil
		}
		return ErrIdempotencyConflict
	}
	prior := p.records[key]
	if prior.record.ID != "" {
		if prior.workflow != m.WorkflowDigest || prior.record.Request.Scope != m.Record.Request.Scope || prior.record.Request.PolicyEpoch != m.Record.Request.PolicyEpoch || prior.record.Request.IntentDigest != m.Record.Request.IntentDigest || prior.record.Request.SessionID != m.Record.Request.SessionID || prior.record.Request.Nonce != m.Record.Request.Nonce || !prior.record.ExpiresAt.Equal(m.Record.ExpiresAt) || m.Event.Scope != m.Record.Request.Scope || m.Event.PolicyEpoch != m.Record.Request.PolicyEpoch {
			return ErrBindingConflict
		}
		if len(prior.events) > 0 {
			last := prior.events[len(prior.events)-1]
			if m.Event.Sequence != last.Sequence+1 {
				return ErrEventSequence
			}
			m.Event.PreviousHash = last.Hash
		}
	} else if m.Event.Sequence != 1 || m.Event.Scope != m.Record.Request.Scope || m.Event.PolicyEpoch != m.Record.Request.PolicyEpoch || m.Event.IntentDigest != m.Record.Request.IntentDigest || m.Event.SessionID != m.Record.Request.SessionID {
		return ErrEventSequence
	}
	m.Event.Hash = hashEvent(m.Event)
	m.Record = cloneRecord(m.Record)
	p.records[key] = approvalMemoryRecord{record: m.Record, workflow: m.WorkflowDigest, events: append(append([]AuditEvent(nil), prior.events...), m.Event)}
	p.idempotency[idem] = fp
	return nil
}
func (p *MemoryPersistence) Load(ctx context.Context, id string) (Record, error) {
	if p == nil || ctx == nil {
		return Record{}, ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := validateOpaque(id, true); err != nil {
		return Record{}, ErrInvalidPersistence
	}
	r, ok := p.records[id]
	if !ok {
		return Record{}, ErrApprovalNotFound
	}
	return cloneRecord(r.record), nil
}

func (p *MemoryPersistence) LoadWithEvents(ctx context.Context, id string) (Record, []AuditEvent, error) {
	if p == nil || ctx == nil {
		return Record{}, nil, ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return Record{}, nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.loadWithEventsLocked(id)
}

func (p *MemoryPersistence) LoadWithEventsAtEpoch(ctx context.Context, id string, expectedEpoch uint64) (Record, []AuditEvent, error) {
	if p == nil || ctx == nil {
		return Record{}, nil, ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return Record{}, nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	record, events, err := p.loadWithEventsLocked(id)
	if err != nil {
		return Record{}, nil, err
	}
	if record.Request.PolicyEpoch != expectedEpoch {
		return Record{}, nil, ErrEpochChanged
	}
	return record, events, nil
}

func (p *MemoryPersistence) loadWithEventsLocked(id string) (Record, []AuditEvent, error) {
	if err := validateOpaque(id, true); err != nil {
		return Record{}, nil, ErrInvalidPersistence
	}
	r, ok := p.records[id]
	if !ok {
		return Record{}, nil, ErrApprovalNotFound
	}
	events := append([]AuditEvent(nil), r.events...)
	if err := validatePersistedEvents(r.record, events); err != nil {
		return Record{}, nil, err
	}
	return cloneRecord(r.record), events, nil
}

func (p *MemoryPersistence) Events(ctx context.Context, id string) ([]AuditEvent, error) {
	_, out, err := p.LoadWithEvents(ctx, id)
	return out, err
}

func validatePersistedEvents(record Record, events []AuditEvent) error {
	var previous string
	for index := range events {
		e := events[index]
		if e.Sequence != uint64(index+1) || e.RequestID != record.ID || e.Scope != record.Request.Scope || e.PolicyEpoch != record.Request.PolicyEpoch || e.IntentDigest != record.Request.IntentDigest || e.WorkflowDigest != record.Request.WorkflowDigest || e.SessionID != record.Request.SessionID || e.Nonce != record.Request.Nonce || e.PreviousHash != previous || e.Hash == "" || hashEvent(e) != e.Hash {
			return ErrInvalidPersistence
		}
		previous = e.Hash
	}
	return nil
}
func validateMutation(m ApprovalMutation) error {
	if validateOpaque(m.IdempotencyKey, true) != nil || validateOpaque(m.Record.ID, true) != nil || m.Record.Request.ID != m.Record.ID || (m.WorkflowDigest != "" && validateOpaque(m.WorkflowDigest, true) != nil) || m.Event.Sequence == 0 || m.Event.At.IsZero() || m.Event.RequestID != m.Record.ID || (m.Event.WorkflowDigest != "" && m.Event.WorkflowDigest != m.WorkflowDigest) {
		return ErrInvalidPersistence
	}
	if err := validateRequest(m.Record.Request); err != nil || validateOpaque(m.Record.Request.Nonce, true) != nil {
		return ErrInvalidPersistence
	}
	if m.Event.Scope != m.Record.Request.Scope || m.Event.PolicyEpoch != m.Record.Request.PolicyEpoch || (m.Event.IntentDigest != "" && m.Event.IntentDigest != m.Record.Request.IntentDigest) || (m.Event.SessionID != "" && m.Event.SessionID != m.Record.Request.SessionID) || (m.Event.Nonce != "" && m.Event.Nonce != m.Record.Request.Nonce) {
		return ErrBindingConflict
	}
	if m.Event.Actor != "" && validateOpaque(m.Event.Actor, false) != nil {
		return ErrInvalidPersistence
	}
	if m.Record.ExpiresAt.IsZero() || m.Record.SubmittedAt.IsZero() || m.Record.ExpiresAt.Before(m.Record.SubmittedAt) {
		return ErrInvalidPersistence
	}
	return nil
}
func mutationFingerprint(m ApprovalMutation) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func hashEvent(e AuditEvent) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ValidateMutationForAdapter exposes contract validation to persistence subpackages.
func ValidateMutationForAdapter(m ApprovalMutation) error { return validateMutation(m) }

// HashBytes returns a lowercase SHA-256 digest for adapter fingerprints.
func HashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// ApplyBatch provides an atomic-capability hook for multi-event mutations.
func (p *MemoryPersistence) ApplyBatch(ctx context.Context, ms []ApprovalMutation) error {
	if p == nil || ctx == nil || len(ms) == 0 {
		return ErrInvalidPersistence
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	records := make(map[string]approvalMemoryRecord, len(p.records))
	for k, v := range p.records {
		v.events = append([]AuditEvent(nil), v.events...)
		v.record = cloneRecord(v.record)
		records[k] = v
	}
	idem := make(map[string]string, len(p.idempotency))
	for k, v := range p.idempotency {
		idem[k] = v
	}
	for _, m := range ms {
		if err := p.applyLocked(ctx, m); err != nil {
			p.records = records
			p.idempotency = idem
			return err
		}
	}
	return nil
}
