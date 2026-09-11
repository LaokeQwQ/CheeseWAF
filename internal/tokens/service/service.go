// Package service provides the durable adapter for scoped management tokens.
//
// The service owns no plaintext credential state.  It creates a secret once,
// persists only its SHA-256 digest, and uses the persistence contract for all
// later authorization and state transitions.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
)

var (
	ErrInvalidConfig           = errors.New("invalid token service configuration")
	ErrInvalidRequest          = errors.New("invalid token service request")
	ErrReplayConflict          = errors.New("token issue or authorization replay conflict")
	ErrEpochMismatch           = errors.New("token policy epoch mismatch")
	ErrEpochUnavailable        = errors.New("token policy epoch unavailable")
	ErrConfirmationRequired    = errors.New("token confirmation required")
	ErrConfirmationReplay      = errors.New("token confirmation has already been used")
	ErrConfirmationUnavailable = errors.New("token confirmation verifier unavailable")
	ErrBlacklisted             = errors.New("token blacklisted")
	ErrCacheUnavailable        = errors.New("token blacklist cache unavailable")
)

// Clock supplies the operation time.  A caller-provided clock keeps issue and
// authorization decisions deterministic in tests and in controlled runtimes.
type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// EpochSource returns the current policy epoch for a tenant.
type EpochSource interface {
	CurrentEpoch(context.Context, string) (uint64, error)
}

// ConfirmationGate is the second-confirmation boundary for never-expiring
// credentials.  Passwords, TOTP values, and session proofs stay outside this
// package.
type ConfirmationGate interface {
	Confirm(context.Context, ConfirmationRequest) error
}

// ConfirmationRequest is the immutable request summary given to the gate.
type ConfirmationRequest struct {
	ID          string
	TenantID    string
	Owner       string
	PolicyEpoch uint64
	Request     tokens.CreateRequest
}

// CacheKey scopes a short-lived blacklist/cache entry to the credential and
// tenant.  SecretDigest is included so a cache implementation cannot confuse
// two credentials that happen to reuse an identifier in different stores.
type CacheKey struct {
	TenantID     string
	TokenID      string
	SecretDigest string
	PolicyEpoch  uint64
}

// CacheEntry is an acceleration hint only; persistence remains authoritative.
type CacheEntry struct {
	TenantID     string
	TokenID      string
	SecretDigest string
	PolicyEpoch  uint64
	ExpiresAt    time.Time
	Revoked      bool
	Metadata     tokens.Metadata
}

// Cache may provide a deny-only blacklist and optional positive cache.  A
// cache hit can deny authorization, but a miss never authorizes by itself.
type Cache interface {
	IsBlacklisted(context.Context, CacheKey) (bool, error)
	Put(context.Context, CacheKey, CacheEntry, time.Duration) error
	Blacklist(context.Context, CacheKey, time.Duration) error
}

type Config struct {
	Persistence      tokens.Persistence
	Clock            Clock
	Epochs           EpochSource
	LeaseID          string
	Cache            Cache
	ConfirmationGate ConfirmationGate
}

type Service struct {
	mu                   sync.Mutex
	persistence          tokens.Persistence
	clock                Clock
	epochs               EpochSource
	leaseID              string
	cache                Cache
	confirmGate          ConfirmationGate
	confirmations        map[string]struct{}
	pendingConfirmations map[string]struct{}
	issueKeys            map[string]struct{}
	pendingIssues        map[string]struct{}
	knownTenants         map[string]struct{}
	statusKeys           map[string]string
	nextCleanupAt        time.Time
	firstCreation        time.Time
	lastCreation         time.Time
}

type IssueRequest struct {
	TenantID       string
	IdempotencyKey string
	ConfirmationID string
	Request        tokens.CreateRequest
}

type ValidateRequest struct {
	TenantID       string
	TokenID        string
	Secret         string
	Permission     string
	Resource       string
	PolicyEpoch    uint64
	IdempotencyKey string
}

type RevokeRequest struct {
	TenantID       string
	TokenID        string
	Actor          string
	Reason         string
	PolicyEpoch    uint64
	IdempotencyKey string
}

type DisableRequest = RevokeRequest

func New(cfg Config) (*Service, error) {
	if cfg.Persistence == nil {
		return nil, ErrInvalidConfig
	}
	leaseID := cfg.LeaseID
	if leaseID == "" {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, fmt.Errorf("%w: lease id: %v", ErrInvalidConfig, err)
		}
		leaseID = "token-service-" + hex.EncodeToString(raw[:])
	}
	if !strictOpaque(leaseID) {
		return nil, fmt.Errorf("%w: invalid lease id", ErrInvalidConfig)
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	return &Service{
		persistence:          cfg.Persistence,
		clock:                cfg.Clock,
		epochs:               cfg.Epochs,
		leaseID:              leaseID,
		cache:                cfg.Cache,
		confirmGate:          cfg.ConfirmationGate,
		confirmations:        make(map[string]struct{}),
		pendingConfirmations: make(map[string]struct{}),
		issueKeys:            make(map[string]struct{}),
		pendingIssues:        make(map[string]struct{}),
		knownTenants:         make(map[string]struct{}),
		statusKeys:           make(map[string]string),
	}, nil
}

func (s *Service) Persistence() tokens.Persistence {
	if s == nil {
		return nil
	}
	return s.persistence
}

func (s *Service) SetCache(cache Cache) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cache = cache
	s.mu.Unlock()
}

func (s *Service) SetConfirmationGate(gate ConfirmationGate) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.confirmGate = gate
	s.mu.Unlock()
}

func (s *Service) Issue(ctx context.Context, req IssueRequest) (tokens.Issued, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return tokens.Issued{}, ctx.Err()
		}
		return tokens.Issued{}, ErrInvalidRequest
	}
	if !strictOpaque(req.TenantID) || !strictOpaque(req.IdempotencyKey) || !strictIdentity(req.Request.Owner) {
		return tokens.Issued{}, ErrInvalidRequest
	}
	now := s.now()
	if now.IsZero() {
		return tokens.Issued{}, ErrInvalidRequest
	}
	now = now.UTC()
	if err := s.requireEpoch(ctx, req.TenantID, req.Request.PolicyEpoch); err != nil {
		return tokens.Issued{}, err
	}
	issueKeyValue := issueKey(req.TenantID, req.IdempotencyKey)
	s.mu.Lock()
	if _, used := s.issueKeys[issueKeyValue]; used {
		s.mu.Unlock()
		return tokens.Issued{}, ErrReplayConflict
	}
	if _, pending := s.pendingIssues[issueKeyValue]; pending {
		s.mu.Unlock()
		return tokens.Issued{}, ErrReplayConflict
	}
	s.pendingIssues[issueKeyValue] = struct{}{}
	confirmationKeyValue := ""
	var gate ConfirmationGate
	if req.Request.NeverExpire {
		if !req.Request.ConfirmNeverExpire || !strictOpaque(req.ConfirmationID) {
			delete(s.pendingIssues, issueKeyValue)
			s.mu.Unlock()
			return tokens.Issued{}, ErrConfirmationRequired
		}
		gate = s.confirmGate
		if gate == nil {
			delete(s.pendingIssues, issueKeyValue)
			s.mu.Unlock()
			return tokens.Issued{}, ErrConfirmationUnavailable
		}
		confirmationKeyValue = confirmationKey(req.TenantID, req.ConfirmationID)
		if _, used := s.confirmations[confirmationKeyValue]; used {
			delete(s.pendingIssues, issueKeyValue)
			s.mu.Unlock()
			return tokens.Issued{}, ErrConfirmationReplay
		}
		if _, pending := s.pendingConfirmations[confirmationKeyValue]; pending {
			delete(s.pendingIssues, issueKeyValue)
			s.mu.Unlock()
			return tokens.Issued{}, ErrConfirmationReplay
		}
		s.pendingConfirmations[confirmationKeyValue] = struct{}{}
	}
	s.mu.Unlock()

	if req.Request.NeverExpire {
		confirmation := ConfirmationRequest{ID: req.ConfirmationID, TenantID: req.TenantID, Owner: req.Request.Owner, PolicyEpoch: req.Request.PolicyEpoch, Request: cloneCreateRequest(req.Request)}
		if err := gate.Confirm(ctx, confirmation); err != nil {
			s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
			return tokens.Issued{}, fmt.Errorf("%w: %v", ErrConfirmationRequired, err)
		}
	}

	permissions, ok := normalize(req.Request.Permissions)
	if !ok {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		return tokens.Issued{}, ErrInvalidRequest
	}
	resources, ok := normalize(req.Request.Resources)
	if len(req.Request.Resources) == 0 {
		resources, ok = normalize(req.Request.Scopes)
	} else if len(req.Request.Scopes) > 0 {
		aliases, aliasesOK := normalize(req.Request.Scopes)
		if !aliasesOK {
			s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
			return tokens.Issued{}, ErrInvalidRequest
		}
		resources, ok = normalize(append(resources, aliases...))
	}
	if !ok {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		return tokens.Issued{}, ErrInvalidRequest
	}
	lifetime, err := tokens.ResolveLifetime(now, req.Request.TTL, time.Time{}, req.Request.NeverExpire, req.Request.ConfirmNeverExpire)
	if err != nil {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		return tokens.Issued{}, err
	}
	id, secret, digest, err := newCredential()
	if err != nil {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		return tokens.Issued{}, err
	}
	meta := tokens.Metadata{ID: id, Owner: req.Request.Owner, Permissions: permissions, Resources: resources, Scopes: append([]string(nil), resources...), Note: strings.TrimSpace(req.Request.Note), PolicyEpoch: req.Request.PolicyEpoch, CreatedAt: now, LastActivityAt: now, ExpiresAt: lifetime.ExpiresAt, NeverExpire: lifetime.NeverExpire}
	persisted := toPersisted(meta, digest, s.leaseID, 1)
	mutation := tokens.Mutation{TenantID: req.TenantID, Token: persisted, ExpectedVersion: 0, LeaseID: s.leaseID, IdempotencyKey: req.IdempotencyKey, Event: tokens.Event{Sequence: 1, Type: tokens.EventCreated, At: now, TokenID: id, Actor: req.Request.Owner}}
	// Re-read the policy epoch immediately before the durable write.  The
	// external epoch source is deliberately called without holding service.mu.
	epochErr := s.requireEpoch(ctx, req.TenantID, req.Request.PolicyEpoch)
	if epochErr != nil {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		return tokens.Issued{}, epochErr
	}
	if err := ctx.Err(); err != nil {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		return tokens.Issued{}, err
	}
	if err := s.persistence.Apply(ctx, mutation); err != nil {
		s.releaseIssueReservation(issueKeyValue, confirmationKeyValue)
		if errors.Is(err, tokens.ErrIdempotencyConflict) {
			return tokens.Issued{}, ErrReplayConflict
		}
		return tokens.Issued{}, err
	}
	s.mu.Lock()
	delete(s.pendingIssues, issueKeyValue)
	s.issueKeys[issueKeyValue] = struct{}{}
	s.knownTenants[req.TenantID] = struct{}{}
	s.recordCreationLocked(now)
	if confirmationKeyValue != "" {
		delete(s.pendingConfirmations, confirmationKeyValue)
		s.confirmations[confirmationKeyValue] = struct{}{}
	}
	cache := s.cache
	s.mu.Unlock()
	if cache != nil {
		_ = cache.Put(ctx, cacheKey(req.TenantID, persisted), CacheEntry{TenantID: req.TenantID, TokenID: id, SecretDigest: digest, PolicyEpoch: meta.PolicyEpoch, ExpiresAt: meta.ExpiresAt, Metadata: cloneMetadata(meta)}, cacheTTL(meta, now))
	}
	return tokens.Issued{Metadata: cloneMetadata(meta), Secret: secret}, nil
}

func (s *Service) releaseIssueReservation(issueKeyValue, confirmationKeyValue string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.pendingIssues, issueKeyValue)
	if confirmationKeyValue != "" {
		delete(s.pendingConfirmations, confirmationKeyValue)
	}
	s.mu.Unlock()
}

func (s *Service) Validate(ctx context.Context, req ValidateRequest) (tokens.Metadata, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return tokens.Metadata{}, ctx.Err()
		}
		return tokens.Metadata{}, ErrInvalidRequest
	}
	if !strictOpaque(req.TenantID) || !strictOpaque(req.TokenID) || req.Secret == "" || !strictOpaque(req.IdempotencyKey) || req.PolicyEpoch == 0 {
		return tokens.Metadata{}, ErrInvalidRequest
	}
	if !strictSelector(req.Permission) || !strictSelector(req.Resource) {
		return tokens.Metadata{}, ErrInvalidRequest
	}
	permission, resource := req.Permission, req.Resource
	now := s.now()
	if now.IsZero() {
		return tokens.Metadata{}, ErrInvalidRequest
	}
	now = now.UTC()
	if err := s.requireEpoch(ctx, req.TenantID, req.PolicyEpoch); err != nil {
		return tokens.Metadata{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	persisted, err := s.persistence.Load(ctx, req.TenantID, req.TokenID)
	if err != nil {
		if errors.Is(err, tokens.ErrTokenNotFound) {
			return tokens.Metadata{}, tokens.ErrNotFound
		}
		return tokens.Metadata{}, err
	}
	if err := validatePersisted(persisted); err != nil {
		return tokens.Metadata{}, err
	}
	key := cacheKey(req.TenantID, persisted)
	if s.cache != nil {
		blacklisted, cacheErr := s.cache.IsBlacklisted(ctx, key)
		if cacheErr != nil {
			return tokens.Metadata{}, fmt.Errorf("%w: %v", ErrCacheUnavailable, cacheErr)
		}
		if blacklisted {
			return tokens.Metadata{}, ErrBlacklisted
		}
	}
	if !constantTimeDigestMatches(req.Secret, persisted.SecretDigest) {
		return tokens.Metadata{}, tokens.ErrInvalidSecret
	}
	if persisted.PolicyEpoch != req.PolicyEpoch {
		return tokens.Metadata{}, ErrEpochMismatch
	}
	if persisted.Revoked {
		return tokens.Metadata{}, tokens.ErrRevoked
	}
	if persisted.Disabled {
		return tokens.Metadata{}, tokens.ErrDisabled
	}
	if !persisted.NeverExpire && !now.Before(persisted.ExpiresAt) {
		return tokens.Metadata{}, tokens.ErrExpired
	}
	if now.Before(persisted.CreatedAt) || now.Before(persisted.LastActivityAt) {
		return tokens.Metadata{}, tokens.ErrInvalidTime
	}
	if now.Sub(persisted.LastActivityAt) >= tokens.InactivityTTL {
		return tokens.Metadata{}, tokens.ErrInactive
	}
	if !matches(persisted.Permissions, permission) {
		return tokens.Metadata{}, tokens.ErrPermissionDenied
	}
	if !matches(persisted.Resources, resource) {
		return tokens.Metadata{}, tokens.ErrResourceDenied
	}

	persisted.LastActivityAt = now
	persisted.Version++
	seq, err := s.nextEventSequence(ctx, req.TenantID, req.TokenID)
	if err != nil {
		return tokens.Metadata{}, err
	}
	mutation := tokens.Mutation{TenantID: req.TenantID, Token: persisted, ExpectedVersion: persisted.Version - 1, LeaseID: persisted.LeaseID, IdempotencyKey: req.IdempotencyKey, Event: tokens.Event{Sequence: seq, Type: tokens.EventAuthorized, At: now, TokenID: req.TokenID, Actor: persisted.Owner}}
	if err := s.persistence.Apply(ctx, mutation); err != nil {
		if errors.Is(err, tokens.ErrIdempotencyConflict) {
			return tokens.Metadata{}, ErrReplayConflict
		}
		return tokens.Metadata{}, err
	}
	return fromPersisted(persisted), nil
}

func (s *Service) Revoke(ctx context.Context, req RevokeRequest) error {
	return s.status(ctx, req, tokens.EventRevoked, true)
}

func (s *Service) Disable(ctx context.Context, req DisableRequest) error {
	return s.status(ctx, req, tokens.EventDisabled, false)
}

func (s *Service) status(ctx context.Context, req RevokeRequest, typ tokens.EventType, revoke bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		if ctx != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInvalidRequest
	}
	if !strictOpaque(req.TenantID) || !strictOpaque(req.TokenID) || !strictOpaque(req.IdempotencyKey) {
		return ErrInvalidRequest
	}
	if req.Actor != "" && !strictIdentity(req.Actor) {
		return ErrInvalidRequest
	}
	now := s.now()
	if now.IsZero() {
		return ErrInvalidRequest
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	statusKey := issueKey(req.TenantID, req.IdempotencyKey)
	statusSignature := fmt.Sprintf("%s\x00%s\x00%s\x00%s", req.TokenID, req.Actor, req.Reason, typ)
	if prior, ok := s.statusKeys[statusKey]; ok {
		if prior == statusSignature {
			return nil
		}
		return ErrReplayConflict
	}
	persisted, err := s.persistence.Load(ctx, req.TenantID, req.TokenID)
	if err != nil {
		if errors.Is(err, tokens.ErrTokenNotFound) {
			return tokens.ErrNotFound
		}
		return err
	}
	if err := validatePersisted(persisted); err != nil {
		return err
	}
	if req.PolicyEpoch != 0 {
		if err := s.requireEpoch(ctx, req.TenantID, req.PolicyEpoch); err != nil {
			return err
		}
	}
	if revoke {
		if persisted.Revoked {
			return tokens.ErrAlreadyRevoked
		}
		persisted.Revoked = true
	} else {
		if persisted.Disabled {
			return tokens.ErrAlreadyDisabled
		}
		persisted.Disabled = true
	}
	persisted.Version++
	seq, err := s.nextEventSequence(ctx, req.TenantID, req.TokenID)
	if err != nil {
		return err
	}
	mutation := tokens.Mutation{TenantID: req.TenantID, Token: persisted, ExpectedVersion: persisted.Version - 1, LeaseID: persisted.LeaseID, IdempotencyKey: req.IdempotencyKey, Event: tokens.Event{Sequence: seq, Type: typ, At: now, TokenID: req.TokenID, Actor: req.Actor, Reason: req.Reason}}
	if err := s.persistence.Apply(ctx, mutation); err != nil {
		if errors.Is(err, tokens.ErrIdempotencyConflict) {
			return ErrReplayConflict
		}
		return err
	}
	if revoke && s.cache != nil {
		if err := s.cache.Blacklist(ctx, cacheKey(req.TenantID, persisted), cacheTTL(fromPersisted(persisted), now)); err != nil {
			return fmt.Errorf("%w: %v", ErrCacheUnavailable, err)
		}
	}
	s.statusKeys[statusKey] = statusSignature
	return nil
}

func (s *Service) Get(ctx context.Context, tenantID, tokenID string) (tokens.Metadata, error) {
	if s == nil || ctx == nil || !strictOpaque(tenantID) || !strictOpaque(tokenID) {
		return tokens.Metadata{}, ErrInvalidRequest
	}
	persisted, err := s.persistence.Load(ctx, tenantID, tokenID)
	if errors.Is(err, tokens.ErrTokenNotFound) {
		return tokens.Metadata{}, tokens.ErrNotFound
	}
	if err != nil {
		return tokens.Metadata{}, err
	}
	if err := validatePersisted(persisted); err != nil {
		return tokens.Metadata{}, err
	}
	return fromPersisted(persisted), nil
}

func (s *Service) List(ctx context.Context, tenantID string) ([]tokens.Metadata, error) {
	if s == nil || ctx == nil || !strictOpaque(tenantID) {
		return nil, ErrInvalidRequest
	}
	items, err := s.persistence.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]tokens.Metadata, 0, len(items))
	for _, item := range items {
		if err := validatePersisted(item); err != nil {
			return nil, err
		}
		out = append(out, fromPersisted(item))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Service) Events(ctx context.Context, tenantID, tokenID string) ([]tokens.Event, error) {
	if s == nil || ctx == nil || !strictOpaque(tenantID) || !strictOpaque(tokenID) {
		return nil, ErrInvalidRequest
	}
	return s.persistence.Events(ctx, tenantID, tokenID)
}

func (s *Service) NextCleanupAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextCleanupAt
}

// Cleanup removes expired or inactive tokens after the one coalesced deadline.
// Supplying tenant IDs limits the scan; with no IDs the service scans tenants
// it has observed through Issue/cleanup calls.
func (s *Service) Cleanup(ctx context.Context, tenantIDs ...string) (int, error) {
	if s == nil || ctx == nil {
		return 0, ErrInvalidRequest
	}
	now := s.now()
	if now.IsZero() {
		return 0, ErrInvalidRequest
	}
	now = now.UTC()
	s.mu.Lock()
	if s.nextCleanupAt.IsZero() || now.Before(s.nextCleanupAt) {
		s.mu.Unlock()
		return 0, nil
	}
	if len(tenantIDs) == 0 {
		for tenant := range s.knownTenants {
			tenantIDs = append(tenantIDs, tenant)
		}
	}
	for _, tenant := range tenantIDs {
		if !strictOpaque(tenant) {
			s.mu.Unlock()
			return 0, ErrInvalidRequest
		}
	}
	removed := 0
	remaining := false
	for _, tenant := range tenantIDs {
		items, err := s.persistence.List(ctx, tenant)
		if err != nil {
			s.mu.Unlock()
			return removed, err
		}
		for _, item := range items {
			if err := validatePersisted(item); err != nil {
				s.mu.Unlock()
				return removed, err
			}
			expired := !item.NeverExpire && !now.Before(item.ExpiresAt)
			inactive := now.Sub(item.LastActivityAt) >= tokens.InactivityTTL
			if !expired && !inactive {
				remaining = true
				continue
			}
			seq, err := s.nextEventSequence(ctx, tenant, item.ID)
			if err != nil {
				s.mu.Unlock()
				return removed, err
			}
			reason := "inactive"
			if expired {
				reason = "expired"
			}
			mutation := tokens.Mutation{TenantID: tenant, Token: item, ExpectedVersion: item.Version, LeaseID: item.LeaseID, IdempotencyKey: "cleanup:" + item.ID + ":" + fmt.Sprint(item.Version), DeleteToken: true, Event: tokens.Event{Sequence: seq, Type: tokens.EventAutoDestroyed, At: now, TokenID: item.ID, Actor: item.Owner, Reason: reason, Notification: true}}
			if err := s.persistence.Apply(ctx, mutation); err != nil {
				if errors.Is(err, tokens.ErrIdempotencyConflict) {
					continue
				}
				s.mu.Unlock()
				return removed, err
			}
			removed++
		}
	}
	allKnownScanned := true
	for tenant := range s.knownTenants {
		found := false
		for _, scanned := range tenantIDs {
			if scanned == tenant {
				found = true
				break
			}
		}
		if !found {
			allKnownScanned = false
			break
		}
	}
	if !remaining && allKnownScanned {
		s.nextCleanupAt = time.Time{}
		s.firstCreation = time.Time{}
		s.lastCreation = time.Time{}
	} else {
		s.nextCleanupAt = now.Add(tokens.CleanupDelay)
	}
	s.mu.Unlock()
	return removed, nil
}

func (s *Service) now() time.Time { return s.clock.Now() }

func (s *Service) requireEpoch(ctx context.Context, tenant string, want uint64) error {
	if want == 0 || s.epochs == nil {
		return ErrEpochUnavailable
	}
	got, err := s.epochs.CurrentEpoch(ctx, tenant)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEpochUnavailable, err)
	}
	if got == 0 || got != want {
		return ErrEpochMismatch
	}
	return nil
}

func (s *Service) nextEventSequence(ctx context.Context, tenant, tokenID string) (uint64, error) {
	events, err := s.persistence.Events(ctx, tenant, tokenID)
	if err != nil {
		if errors.Is(err, tokens.ErrTokenNotFound) {
			return 1, nil
		}
		return 0, err
	}
	if len(events) == 0 {
		return 1, nil
	}
	return events[len(events)-1].Sequence + 1, nil
}

func (s *Service) recordCreationLocked(now time.Time) {
	if s.firstCreation.IsZero() {
		s.firstCreation = now
	}
	s.lastCreation = now
	deadline := now.Add(tokens.CleanupDelay)
	capAt := s.firstCreation.Add(time.Hour)
	if deadline.After(capAt) {
		deadline = capAt
	}
	s.nextCleanupAt = deadline
}

func strictOpaque(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

func strictIdentity(value string) bool { return strictOpaque(value) }

func strictSelector(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.ContainsFunc(value, unicode.IsSpace) && !strings.ContainsFunc(value, unicode.IsControl)
}

func normalize(values []string) ([]string, bool) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsFunc(value, unicode.IsControl) {
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

func matches(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted || value == "*" {
			return true
		}
	}
	return false
}

func newCredential() (string, string, string, error) {
	var raw [48]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", "", err
	}
	secret := hex.EncodeToString(raw[:])
	id := "tok_" + hex.EncodeToString(raw[:16])
	sum := sha256.Sum256([]byte(secret))
	return id, secret, hex.EncodeToString(sum[:]), nil
}

func constantTimeDigestMatches(secret, digest string) bool {
	sum := sha256.Sum256([]byte(secret))
	want := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(digest)) == 1
}

func toPersisted(meta tokens.Metadata, digest, lease string, version uint64) tokens.PersistedToken {
	return tokens.PersistedToken{ID: meta.ID, Owner: meta.Owner, Permissions: append([]string(nil), meta.Permissions...), Resources: append([]string(nil), meta.Resources...), Scopes: append([]string(nil), meta.Scopes...), Note: meta.Note, PolicyEpoch: meta.PolicyEpoch, CreatedAt: meta.CreatedAt, ExpiresAt: meta.ExpiresAt, NeverExpire: meta.NeverExpire, Disabled: meta.Disabled, Revoked: meta.Revoked, LastActivityAt: meta.LastActivityAt, SecretDigest: digest, LeaseID: lease, Version: version}
}

func fromPersisted(item tokens.PersistedToken) tokens.Metadata {
	resources := append([]string(nil), item.Resources...)
	scopes := append([]string(nil), item.Scopes...)
	if len(scopes) == 0 {
		scopes = append([]string(nil), resources...)
	}
	return tokens.Metadata{ID: item.ID, Owner: item.Owner, Permissions: append([]string(nil), item.Permissions...), Resources: resources, Scopes: scopes, Note: item.Note, PolicyEpoch: item.PolicyEpoch, CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt, NeverExpire: item.NeverExpire, Disabled: item.Disabled, Revoked: item.Revoked, LastActivityAt: item.LastActivityAt}
}

func cloneMetadata(in tokens.Metadata) tokens.Metadata {
	in.Permissions = append([]string(nil), in.Permissions...)
	in.Resources = append([]string(nil), in.Resources...)
	in.Scopes = append([]string(nil), in.Scopes...)
	return in
}

func cloneCreateRequest(in tokens.CreateRequest) tokens.CreateRequest {
	in.Permissions = append([]string(nil), in.Permissions...)
	in.Resources = append([]string(nil), in.Resources...)
	in.Scopes = append([]string(nil), in.Scopes...)
	return in
}

func validatePersisted(item tokens.PersistedToken) error {
	if !strictOpaque(item.ID) || !strictIdentity(item.Owner) || item.PolicyEpoch == 0 || item.Version == 0 || item.CreatedAt.IsZero() || item.LastActivityAt.IsZero() || item.LastActivityAt.Before(item.CreatedAt) || !strictOpaque(item.LeaseID) {
		return tokens.ErrInvalidPersistence
	}
	if len(item.SecretDigest) != 64 || item.SecretDigest != strings.ToLower(item.SecretDigest) {
		return tokens.ErrInvalidPersistence
	}
	if _, err := hex.DecodeString(item.SecretDigest); err != nil {
		return tokens.ErrInvalidPersistence
	}
	if item.NeverExpire && !item.ExpiresAt.IsZero() {
		return tokens.ErrInvalidPersistence
	}
	if !item.NeverExpire && (item.ExpiresAt.IsZero() || !item.ExpiresAt.After(item.CreatedAt)) {
		return tokens.ErrInvalidPersistence
	}
	if !item.ExpiresAt.IsZero() && item.ExpiresAt.Sub(item.CreatedAt) > tokens.MaxTTL {
		return tokens.ErrInvalidPersistence
	}
	if !validSnapshot(item.Permissions) || (!validSnapshot(item.Resources) && !validSnapshot(item.Scopes)) {
		return tokens.ErrInvalidPersistence
	}
	return nil
}

func validSnapshot(values []string) bool {
	if len(values) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !strictSelector(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func cacheKey(tenant string, item tokens.PersistedToken) CacheKey {
	return CacheKey{TenantID: tenant, TokenID: item.ID, SecretDigest: item.SecretDigest, PolicyEpoch: item.PolicyEpoch}
}

func cacheTTL(meta tokens.Metadata, now time.Time) time.Duration {
	if meta.NeverExpire || meta.ExpiresAt.IsZero() {
		return tokens.InactivityTTL
	}
	remaining := meta.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return time.Second
	}
	return remaining
}

func issueKey(tenant, key string) string        { return tenant + "\x00" + key }
func confirmationKey(tenant, key string) string { return tenant + "\x00" + key }
