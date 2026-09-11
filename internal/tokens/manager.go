// Package tokens defines the in-process contract for scoped management tokens.
//
// The package deliberately has no persistence, network, goroutine, or wall
// clock dependency. Callers provide the current time to every operation and a
// storage/runtime adapter may later project this contract onto PostgreSQL and
// Redis without changing its fail-closed semantics.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	DefaultTTL    = 90 * 24 * time.Hour
	MaxTTL        = 365 * 24 * time.Hour
	InactivityTTL = 180 * 24 * time.Hour
	CleanupDelay  = 10 * time.Minute
)

var (
	ErrInvalidRequest             = errors.New("invalid token request")
	ErrInvalidTTL                 = errors.New("invalid token TTL")
	ErrTTLExceeded                = errors.New("token TTL exceeds platform maximum")
	ErrSecondConfirmationRequired = errors.New("second confirmation is required for non-expiring tokens")
	ErrNotFound                   = errors.New("token not found")
	ErrInvalidSecret              = errors.New("invalid token secret")
	ErrPermissionDenied           = errors.New("token permission denied")
	ErrResourceDenied             = errors.New("token resource denied")
	ErrExpired                    = errors.New("token expired")
	ErrInactive                   = errors.New("token inactive")
	ErrDisabled                   = errors.New("token disabled")
	ErrRevoked                    = errors.New("token revoked")
	ErrAlreadyDisabled            = errors.New("token already disabled")
	ErrAlreadyRevoked             = errors.New("token already revoked")
	ErrInvalidTime                = errors.New("operation time precedes token state")
)

// EventType is an append-only state transition or notification category.
type EventType string

const (
	EventCreated       EventType = "created"
	EventAuthorized    EventType = "authorized"
	EventDisabled      EventType = "disabled"
	EventRevoked       EventType = "revoked"
	EventAutoDestroyed EventType = "auto_destroyed"
)

// CreateRequest controls a token's immutable capability snapshot.
type CreateRequest struct {
	Owner       string
	Permissions []string
	Resources   []string
	// Scopes is a compatibility alias for resource/interface ranges. When
	// Resources is empty, Scopes supplies the ranges; when both are present,
	// they are merged and de-duplicated.
	Scopes             []string
	Note               string
	PolicyEpoch        uint64
	TTL                time.Duration
	NeverExpire        bool
	ConfirmNeverExpire bool
}

// Metadata is safe to return to a UI or API: it never contains the secret.
type Metadata struct {
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
}

// Issued is returned exactly at creation time. Secret is not retained in
// Metadata or exposed by Get/List; callers must deliver it to the operator
// using a one-time channel appropriate to the UI.
type Issued struct {
	Metadata Metadata
	Secret   string
}

// Lifetime is the validated lifetime selected for a token. A zero ExpiresAt
// is reserved for an explicitly confirmed non-expiring token.
type Lifetime struct {
	ExpiresAt   time.Time
	NeverExpire bool
}

// Event is an immutable audit/notification snapshot. AutoDestroyed events
// have Notification=true so adapters can enqueue a user notification.
type Event struct {
	Sequence     uint64
	Type         EventType
	At           time.Time
	TokenID      string
	Actor        string
	Reason       string
	Notification bool
}

type record struct {
	metadata Metadata
	secret   [32]byte
}

// Manager is a concurrency-safe in-memory implementation of the contract.
type Manager struct {
	mu            sync.RWMutex
	tokens        map[string]record
	events        []Event
	sequence      uint64
	cleanupAt     time.Time
	firstCreation time.Time
	lastCreation  time.Time
}

func NewManager() *Manager { return &Manager{tokens: make(map[string]record)} }

// ResolveLifetime applies the platform token lifetime policy without reading
// a wall clock. Callers must provide the operation time explicitly so API,
// CLI and durable adapters make the same decision. An omitted lifetime gets
// DefaultTTL; an explicitly non-expiring lifetime needs a second confirmation
// and cannot carry a TTL or absolute expiry.
func ResolveLifetime(now time.Time, ttl time.Duration, expiresAt time.Time, neverExpire, confirmNeverExpire bool) (Lifetime, error) {
	if now.IsZero() {
		return Lifetime{}, ErrInvalidTTL
	}
	now = now.UTC()
	expiresAt = expiresAt.UTC()
	if neverExpire {
		if !confirmNeverExpire {
			return Lifetime{}, ErrSecondConfirmationRequired
		}
		if ttl != 0 || !expiresAt.IsZero() {
			return Lifetime{}, ErrInvalidTTL
		}
		return Lifetime{NeverExpire: true}, nil
	}
	if ttl < 0 || (!expiresAt.IsZero() && ttl != 0) {
		return Lifetime{}, ErrInvalidTTL
	}
	if !expiresAt.IsZero() {
		if !expiresAt.After(now) {
			return Lifetime{}, ErrInvalidTTL
		}
		if expiresAt.After(now.Add(MaxTTL)) {
			return Lifetime{}, ErrTTLExceeded
		}
		return Lifetime{ExpiresAt: expiresAt}, nil
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl <= 0 {
		return Lifetime{}, ErrInvalidTTL
	}
	if ttl > MaxTTL {
		return Lifetime{}, ErrTTLExceeded
	}
	return Lifetime{ExpiresAt: now.Add(ttl)}, nil
}

// Create validates and stores an immutable capability snapshot. The cleanup
// timer is deliberately a single coalesced deadline. New creations slide the
// ten-minute window but cannot move it past the first creation plus one hour.
func (m *Manager) Create(now time.Time, req CreateRequest) (Issued, error) {
	if !strictIdentity(req.Owner) || len(req.Permissions) == 0 || (len(req.Resources) == 0 && len(req.Scopes) == 0) || req.PolicyEpoch == 0 || now.IsZero() {
		return Issued{}, ErrInvalidRequest
	}
	permissions, ok := normalize(req.Permissions)
	if !ok {
		return Issued{}, ErrInvalidRequest
	}
	resources, ok := normalize(req.Resources)
	if len(req.Resources) == 0 {
		resources, ok = normalize(req.Scopes)
	} else if len(req.Scopes) > 0 {
		aliases, aliasesOK := normalize(req.Scopes)
		if !aliasesOK {
			return Issued{}, ErrInvalidRequest
		}
		resources, ok = normalize(append(resources, aliases...))
	}
	if !ok {
		return Issued{}, ErrInvalidRequest
	}
	lifetime, err := ResolveLifetime(now, req.TTL, time.Time{}, req.NeverExpire, req.ConfirmNeverExpire)
	if err != nil {
		return Issued{}, err
	}

	id, secret, digest, err := newCredential()
	if err != nil {
		return Issued{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if _, exists := m.tokens[id]; !exists {
			break
		}
		id, secret, digest, err = newCredential()
		if err != nil {
			return Issued{}, err
		}
	}
	meta := Metadata{ID: id, Owner: req.Owner, Permissions: permissions, Resources: resources, Scopes: append([]string(nil), resources...), Note: req.Note, PolicyEpoch: req.PolicyEpoch, CreatedAt: now, LastActivityAt: now, NeverExpire: lifetime.NeverExpire, ExpiresAt: lifetime.ExpiresAt}
	m.tokens[id] = record{metadata: cloneMetadata(meta), secret: digest}
	if m.firstCreation.IsZero() {
		m.firstCreation = now
	}
	m.lastCreation = now
	m.cleanupAt = minTime(m.lastCreation.Add(CleanupDelay), m.firstCreation.Add(time.Hour))
	m.appendEvent(now, EventCreated, id, req.Owner, "", false)
	return Issued{Metadata: cloneMetadata(meta), Secret: secret}, nil
}

// Get returns a defensive metadata snapshot. now is accepted to keep all
// caller-facing operations explicit about their time source; it is not used.
func (m *Manager) Get(now time.Time, id string) (Metadata, bool) {
	if !strictIdentity(id) {
		return Metadata{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.tokens[id]
	if !ok {
		return Metadata{}, false
	}
	return cloneMetadata(r.metadata), true
}

func (m *Manager) List(now time.Time) []Metadata {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Metadata, 0, len(m.tokens))
	for _, r := range m.tokens {
		out = append(out, cloneMetadata(r.metadata))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Authorize verifies secret, lifetime, immutable permission/resource scope,
// and status. A successful authorization records the supplied time as the
// latest activity, never as a wall-clock lookup.
func (m *Manager) Authorize(now time.Time, id, secret, permission, resource string) (Metadata, error) {
	if !strictIdentity(id) || !strictIdentity(permission) || !strictIdentity(resource) {
		return Metadata{}, ErrInvalidRequest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.tokens[id]
	if !ok {
		return Metadata{}, ErrNotFound
	}
	if now.IsZero() || now.Before(r.metadata.CreatedAt) || now.Before(r.metadata.LastActivityAt) {
		return Metadata{}, ErrInvalidTime
	}
	digest := hashSecret(secret)
	if subtle.ConstantTimeCompare(digest[:], r.secret[:]) != 1 {
		return Metadata{}, ErrInvalidSecret
	}
	if r.metadata.Revoked {
		return Metadata{}, ErrRevoked
	}
	if r.metadata.Disabled {
		return Metadata{}, ErrDisabled
	}
	if !r.metadata.NeverExpire && !now.Before(r.metadata.ExpiresAt) {
		return Metadata{}, ErrExpired
	}
	if now.Sub(r.metadata.LastActivityAt) >= InactivityTTL {
		return Metadata{}, ErrInactive
	}
	if !matches(r.metadata.Permissions, permission) {
		return Metadata{}, ErrPermissionDenied
	}
	if !matches(r.metadata.Resources, resource) {
		return Metadata{}, ErrResourceDenied
	}
	r.metadata.LastActivityAt = now
	m.tokens[id] = r
	m.appendEvent(now, EventAuthorized, id, r.metadata.Owner, "", false)
	return cloneMetadata(r.metadata), nil
}

func (m *Manager) Disable(now time.Time, id, reason string) error {
	return m.setStatus(now, id, strings.TrimSpace(reason), false)
}

func (m *Manager) Revoke(now time.Time, id, reason string) error {
	return m.setStatus(now, id, strings.TrimSpace(reason), true)
}

func (m *Manager) setStatus(now time.Time, id, reason string, revoke bool) error {
	if !strictIdentity(id) {
		return ErrInvalidRequest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.tokens[id]
	if !ok {
		return ErrNotFound
	}
	if now.IsZero() || now.Before(r.metadata.CreatedAt) {
		return ErrInvalidTime
	}
	if revoke {
		if r.metadata.Revoked {
			return ErrAlreadyRevoked
		}
		r.metadata.Revoked = true
		m.tokens[id] = r
		m.appendEvent(now, EventRevoked, id, r.metadata.Owner, reason, false)
		return nil
	}
	if r.metadata.Disabled {
		return ErrAlreadyDisabled
	}
	r.metadata.Disabled = true
	m.tokens[id] = r
	m.appendEvent(now, EventDisabled, id, r.metadata.Owner, reason, false)
	return nil
}

// NextCleanupAt exposes the coalesced timer to an external scheduler.
func (m *Manager) NextCleanupAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cleanupAt
}

// Cleanup performs no work before the coalesced deadline. It removes expired
// or inactive tokens in one pass and schedules the next pass. Authorization
// remains fail-closed even when cleanup has not run yet.
func (m *Manager) Cleanup(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.IsZero() || m.cleanupAt.IsZero() || now.Before(m.cleanupAt) {
		return 0
	}
	removed := 0
	for id, r := range m.tokens {
		expired := !r.metadata.NeverExpire && !now.Before(r.metadata.ExpiresAt)
		inactive := now.Sub(r.metadata.LastActivityAt) >= InactivityTTL
		if !expired && !inactive {
			continue
		}
		delete(m.tokens, id)
		reason := "inactive"
		if expired {
			reason = "expired"
		}
		m.appendEvent(now, EventAutoDestroyed, id, r.metadata.Owner, reason, true)
		removed++
	}
	if len(m.tokens) == 0 {
		m.cleanupAt = time.Time{}
		m.firstCreation = time.Time{}
		m.lastCreation = time.Time{}
	} else {
		m.cleanupAt = now.Add(CleanupDelay)
	}
	return removed
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (m *Manager) Events() []Event {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}

func (m *Manager) appendEvent(at time.Time, typ EventType, id, actor, reason string, notification bool) {
	m.sequence++
	m.events = append(m.events, Event{Sequence: m.sequence, Type: typ, At: at, TokenID: id, Actor: actor, Reason: reason, Notification: notification})
}

func newCredential() (string, string, [32]byte, error) {
	var raw [48]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", [32]byte{}, err
	}
	secret := hex.EncodeToString(raw[:])
	digest := hashSecret(secret)
	return "tok_" + hex.EncodeToString(raw[:16]), secret, digest, nil
}

func hashSecret(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

func normalize(values []string) ([]string, bool) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !strictIdentity(value) {
			return nil, false
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, len(out) > 0
}

func strictIdentity(value string) bool {
	return value != "" && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}

func matches(values []string, wanted string) bool {
	if wanted == "" {
		return false
	}
	for _, value := range values {
		if value == wanted || value == "*" {
			return true
		}
	}
	return false
}

func cloneMetadata(in Metadata) Metadata {
	in.Permissions = append([]string(nil), in.Permissions...)
	in.Resources = append([]string(nil), in.Resources...)
	in.Scopes = append([]string(nil), in.Scopes...)
	return in
}
