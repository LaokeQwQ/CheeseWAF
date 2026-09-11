package tokens

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// PersistedToken is the durable, secret-free representation of token state.
// SecretDigest is the SHA-256 hex digest of the one-time secret; plaintext
// secrets must never cross a persistence boundary. Version is incremented for
// every state transition and LeaseID fences concurrent writers.
type PersistedToken struct {
	ID             string
	Owner          string
	Permissions    []string
	Resources      []string
	Scopes         []string
	Note           string
	PolicyEpoch    uint64
	CreatedAt      time.Time
	ExpiresAt      time.Time
	NeverExpire    bool
	Disabled       bool
	Revoked        bool
	LastActivityAt time.Time
	SecretDigest   string
	LeaseID        string
	Version        uint64
}

// Mutation atomically records a token snapshot and one append-only audit event.
// ExpectedVersion implements optimistic concurrency; LeaseID is a fencing
// value assigned by the control plane. DeleteToken is used for auto-destroy: the
// event remains durable after the token row is removed.
type Mutation struct {
	TenantID        string
	Token           PersistedToken
	Event           Event
	ExpectedVersion uint64
	LeaseID         string
	IdempotencyKey  string
	DeleteToken     bool
}

// Persistence is the narrow boundary consumed by a future TokenService.
// Implementations must be durable and fail closed; absence of a PostgreSQL
// connection must not be implemented as a silent SQLite fallback.
type Persistence interface {
	Apply(ctx context.Context, mutation Mutation) error
	Load(ctx context.Context, tenantID, tokenID string) (PersistedToken, error)
	List(ctx context.Context, tenantID string) ([]PersistedToken, error)
	Events(ctx context.Context, tenantID, tokenID string) ([]Event, error)
}

var (
	ErrInvalidPersistence  = errors.New("invalid token persistence record")
	ErrVersionConflict     = errors.New("token persistence version conflict")
	ErrLeaseConflict       = errors.New("token persistence lease conflict")
	ErrIdempotencyConflict = errors.New("token persistence idempotency conflict")
	ErrTokenNotFound       = errors.New("persisted token not found")
)

func validatePersistedMutation(m Mutation) error {
	if !strictIdentity(m.TenantID) || !strictIdentity(m.Token.ID) || !strictIdentity(m.Token.Owner) || !strictIdentity(m.IdempotencyKey) || !strictIdentity(m.LeaseID) {
		return ErrInvalidPersistence
	}
	if m.Event.TokenID != m.Token.ID || m.Event.Sequence == 0 || m.Event.At.IsZero() || strings.TrimSpace(string(m.Event.Type)) == "" {
		return ErrInvalidPersistence
	}
	if m.Event.Actor != "" && !strictIdentity(m.Event.Actor) || !validIdentityList(m.Token.Permissions) || !validIdentityList(m.Token.Resources) || !validIdentityList(m.Token.Scopes) {
		return ErrInvalidPersistence
	}
	if len(m.Token.SecretDigest) != 64 || m.Token.SecretDigest != strings.ToLower(m.Token.SecretDigest) || !isHexDigest(m.Token.SecretDigest) {
		return ErrInvalidPersistence
	}
	if m.Token.Version == 0 && !m.DeleteToken {
		return ErrInvalidPersistence
	}
	if m.DeleteToken && m.Token.Version == 0 {
		return ErrInvalidPersistence
	}
	if m.Token.PolicyEpoch == 0 || m.Token.CreatedAt.IsZero() || m.Token.LastActivityAt.IsZero() {
		return ErrInvalidPersistence
	}
	if m.Token.LastActivityAt.Before(m.Token.CreatedAt) {
		return ErrInvalidPersistence
	}
	if m.Token.NeverExpire && !m.Token.ExpiresAt.IsZero() {
		return ErrInvalidPersistence
	}
	if !m.Token.ExpiresAt.IsZero() && !m.Token.ExpiresAt.After(m.Token.CreatedAt) {
		return ErrInvalidPersistence
	}
	if !m.Token.ExpiresAt.IsZero() && m.Token.ExpiresAt.Sub(m.Token.CreatedAt) > MaxTTL {
		return ErrInvalidPersistence
	}
	if !m.Token.NeverExpire && m.Token.ExpiresAt.IsZero() {
		return ErrInvalidPersistence
	}
	return nil
}

func validIdentityList(values []string) bool {
	for _, value := range values {
		if !strictIdentity(value) {
			return false
		}
	}
	return true
}

func isHexDigest(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

type memoryRecord struct {
	token  PersistedToken
	events []Event
}

// MemoryPersistence is a deterministic transaction fake for adapter tests.
// It is intentionally not a production durability implementation.
type MemoryPersistence struct {
	mu          sync.RWMutex
	records     map[string]memoryRecord
	idempotency map[string]Mutation
}

func NewMemoryPersistence() *MemoryPersistence {
	return &MemoryPersistence{records: make(map[string]memoryRecord), idempotency: make(map[string]Mutation)}
}

func (p *MemoryPersistence) Apply(ctx context.Context, mutation Mutation) error {
	if p == nil || ctx == nil {
		return ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validatePersistedMutation(mutation); err != nil {
		return err
	}
	key := mutation.TenantID + "\x00" + mutation.Token.ID
	idemKey := mutation.TenantID + "\x00" + mutation.IdempotencyKey
	p.mu.Lock()
	defer p.mu.Unlock()
	if prior, ok := p.idempotency[idemKey]; ok {
		if sameMutation(prior, mutation) {
			return nil
		}
		return ErrIdempotencyConflict
	}
	record, exists := p.records[key]
	if !exists {
		if mutation.ExpectedVersion != 0 || mutation.Token.Version != 1 || mutation.DeleteToken {
			return ErrVersionConflict
		}
	} else {
		if record.token.LeaseID != mutation.LeaseID {
			return ErrLeaseConflict
		}
		if mutation.ExpectedVersion != record.token.Version || mutation.Token.Version != record.token.Version+1 {
			return ErrVersionConflict
		}
	}
	if len(record.events) > 0 && mutation.Event.Sequence != record.events[len(record.events)-1].Sequence+1 {
		return ErrVersionConflict
	}
	if mutation.DeleteToken {
		delete(p.records, key)
		record.events = append(cloneEvents(record.events), mutation.Event)
		p.records[key] = memoryRecord{events: record.events}
	} else {
		p.records[key] = memoryRecord{token: clonePersistedToken(mutation.Token), events: append(cloneEvents(record.events), mutation.Event)}
	}
	p.idempotency[idemKey] = cloneMutation(mutation)
	return nil
}

func (p *MemoryPersistence) Load(ctx context.Context, tenantID, tokenID string) (PersistedToken, error) {
	if p == nil || ctx == nil {
		return PersistedToken{}, ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return PersistedToken{}, err
	}
	if !strictIdentity(tenantID) || !strictIdentity(tokenID) {
		return PersistedToken{}, ErrInvalidPersistence
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	record, ok := p.records[tenantID+"\x00"+tokenID]
	if !ok || record.token.ID == "" {
		return PersistedToken{}, ErrTokenNotFound
	}
	return clonePersistedToken(record.token), nil
}

func (p *MemoryPersistence) List(ctx context.Context, tenantID string) ([]PersistedToken, error) {
	if p == nil || ctx == nil {
		return nil, ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strictIdentity(tenantID) {
		return nil, ErrInvalidPersistence
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	prefix := tenantID + "\x00"
	out := make([]PersistedToken, 0)
	for key, record := range p.records {
		if strings.HasPrefix(key, prefix) && record.token.ID != "" {
			out = append(out, clonePersistedToken(record.token))
		}
	}
	return out, nil
}

func (p *MemoryPersistence) Events(ctx context.Context, tenantID, tokenID string) ([]Event, error) {
	if p == nil || ctx == nil {
		return nil, ErrInvalidPersistence
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strictIdentity(tenantID) || !strictIdentity(tokenID) {
		return nil, ErrInvalidPersistence
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	record, ok := p.records[tenantID+"\x00"+tokenID]
	if !ok {
		return nil, ErrTokenNotFound
	}
	return cloneEvents(record.events), nil
}

func sameMutation(a, b Mutation) bool {
	return a.TenantID == b.TenantID && a.LeaseID == b.LeaseID && a.IdempotencyKey == b.IdempotencyKey && a.ExpectedVersion == b.ExpectedVersion && a.DeleteToken == b.DeleteToken && samePersistedToken(a.Token, b.Token) && a.Event == b.Event
}

func samePersistedToken(a, b PersistedToken) bool {
	if a.ID != b.ID || a.Owner != b.Owner || a.Note != b.Note || a.PolicyEpoch != b.PolicyEpoch || !a.CreatedAt.Equal(b.CreatedAt) || !a.ExpiresAt.Equal(b.ExpiresAt) || a.NeverExpire != b.NeverExpire || a.Disabled != b.Disabled || a.Revoked != b.Revoked || !a.LastActivityAt.Equal(b.LastActivityAt) || a.SecretDigest != b.SecretDigest || a.LeaseID != b.LeaseID || a.Version != b.Version {
		return false
	}
	return slicesEqual(a.Permissions, b.Permissions) && slicesEqual(a.Resources, b.Resources) && slicesEqual(a.Scopes, b.Scopes)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func clonePersistedToken(in PersistedToken) PersistedToken {
	in.Permissions = append([]string(nil), in.Permissions...)
	in.Resources = append([]string(nil), in.Resources...)
	in.Scopes = append([]string(nil), in.Scopes...)
	return in
}
func cloneEvents(in []Event) []Event     { return append([]Event(nil), in...) }
func cloneMutation(in Mutation) Mutation { in.Token = clonePersistedToken(in.Token); return in }
