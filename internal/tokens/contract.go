// Package tokens defines the in-process contract for scoped management tokens.
//
// The package deliberately has no persistence, network, goroutine, or wall
// clock dependency. Callers provide the current time to every operation and a
// storage/runtime adapter may later project this contract onto PostgreSQL and
// Redis without changing its fail-closed semantics.
package tokens

import (
	"errors"
	"strings"
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
	Name        string
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
	Name           string
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

// strictIdentity rejects whitespace, control and format characters in identity
// fields instead of silently trimming them.
func strictIdentity(value string) bool {
	return value != "" && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	})
}
