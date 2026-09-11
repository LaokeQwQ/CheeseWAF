// Package redis defines the Redis short-state boundary without a Redis client.
// Redis is an acceleration/coordination layer only: durable control truth stays
// in PostgreSQL/native consensus and must be revalidated by integration code.
package redis

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Status uint8

const (
	StatusAvailable Status = iota
	StatusUnavailable
	StatusTimeout
	StatusUnknownInstance
)

type Operation uint8

const (
	OperationLease Operation = iota
	OperationLock
	OperationBlacklist
	OperationCache
)

type Mode uint8

const (
	ModeRedis Mode = iota
	ModeLocal
	ModeFailClosed
	ModeCacheMiss
)

func (m Mode) String() string {
	switch m {
	case ModeRedis:
		return "redis"
	case ModeLocal:
		return "local"
	case ModeFailClosed:
		return "fail-closed"
	case ModeCacheMiss:
		return "cache-miss"
	default:
		return "unknown"
	}
}

type Policy struct {
	MaxLocalTTL     time.Duration
	MaxLocalEntries int
}

var (
	ErrEpochRequired = errors.New("policy epoch is required")
	ErrInvalidTTL    = errors.New("TTL must be positive")
	ErrLocalCapacity = errors.New("local fallback capacity exhausted")
	ErrEpochMismatch = errors.New("policy epoch mismatch")
	ErrInvalidLease  = errors.New("invalid local lease")
	ErrExpired       = errors.New("local state expired")
)

type Decision struct {
	Mode Mode
	TTL  time.Duration
}

// Evaluate is the integration contract for Redis-backed short state. An
// unknown instance is never treated as the current Redis; leases/locks and
// blacklist writes fail closed, while cache reads degrade to a miss.
func Evaluate(p Policy, op Operation, status Status, epoch uint64, ttl time.Duration) (Decision, error) {
	if epoch == 0 {
		return Decision{}, ErrEpochRequired
	}
	if ttl <= 0 {
		return Decision{}, ErrInvalidTTL
	}
	switch status {
	case StatusAvailable:
		return Decision{Mode: ModeRedis, TTL: ttl}, nil
	case StatusUnknownInstance:
		if op == OperationCache {
			return Decision{Mode: ModeCacheMiss}, nil
		}
		return Decision{Mode: ModeFailClosed}, nil
	case StatusUnavailable, StatusTimeout:
		if op == OperationCache {
			return Decision{Mode: ModeCacheMiss}, nil
		}
		if (op == OperationLease || op == OperationLock) && p.MaxLocalEntries > 0 && p.MaxLocalTTL > 0 && ttl <= p.MaxLocalTTL {
			return Decision{Mode: ModeLocal, TTL: ttl}, nil
		}
		return Decision{Mode: ModeFailClosed}, nil
	default:
		return Decision{Mode: ModeFailClosed}, nil
	}
}

type localEntry struct {
	op         Operation
	key, token string
	epoch      uint64
	value      []byte
	expiresAt  time.Time
}
type LocalState struct {
	mu      sync.Mutex
	policy  Policy
	entries map[localKey]localEntry
}

// InvalidateBeforeEpoch removes reservations and cached values from older
// policy generations. A caller must invoke this only after the durable fence
// has advanced; entries from an older generation are never reusable.
func (s *LocalState) InvalidateBeforeEpoch(epoch uint64) {
	if s == nil || epoch == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, entry := range s.entries {
		if entry.epoch < epoch {
			delete(s.entries, key)
		}
	}
}

type localKey struct {
	op  Operation
	key string
}

func NewLocalState(p Policy) *LocalState {
	return &LocalState{policy: p, entries: make(map[localKey]localEntry)}
}
func (s *LocalState) prune(now time.Time) {
	for k, e := range s.entries {
		if !now.Before(e.expiresAt) {
			delete(s.entries, k)
		}
	}
}
func (s *LocalState) Reserve(op Operation, key string, epoch uint64, ttl time.Duration, now time.Time) (string, error) {
	if op != OperationLease && op != OperationLock {
		return "", ErrInvalidLease
	}
	if key == "" || epoch == 0 || ttl <= 0 || s.policy.MaxLocalTTL <= 0 || ttl > s.policy.MaxLocalTTL {
		return "", ErrInvalidLease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	for _, existing := range s.entries {
		if existing.op == op && existing.key == key && existing.epoch == epoch && now.Before(existing.expiresAt) {
			return "", ErrLeaseBusy
		}
	}
	if len(s.entries) >= s.policy.MaxLocalEntries {
		return "", ErrLocalCapacity
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	token := hex.EncodeToString(id)
	s.entries[localKey{op: op, key: token}] = localEntry{op: op, key: key, token: token, epoch: epoch, expiresAt: now.Add(ttl)}
	return token, nil
}
func (s *LocalState) Release(token string, op Operation, key string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var e localEntry
	var found localKey
	var ok bool
	for k, candidate := range s.entries {
		if candidate.token == token {
			e, found, ok = candidate, k, true
			break
		}
	}
	if !ok {
		return ErrInvalidLease
	}
	if e.epoch != epoch {
		return ErrEpochMismatch
	}
	if e.op != op || e.key != key {
		return ErrInvalidLease
	}
	delete(s.entries, found)
	return nil
}

// Valid checks a local fallback reservation at the point of use. Callers pass
// the clock explicitly so adapters remain deterministic and bounded.
func (s *LocalState) Valid(token string, op Operation, key string, epoch uint64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var e localEntry
	var found localKey
	var ok bool
	for k, candidate := range s.entries {
		if candidate.token == token {
			e, found, ok = candidate, k, true
			break
		}
	}
	if !ok {
		return ErrInvalidLease
	}
	if e.epoch != epoch {
		return ErrEpochMismatch
	}
	if e.op != op || e.key != key {
		return ErrInvalidLease
	}
	if !now.Before(e.expiresAt) {
		delete(s.entries, found)
		return ErrExpired
	}
	return nil
}
func (s *LocalState) MarkBlacklist(key string, epoch uint64, ttl time.Duration, now time.Time) error {
	return s.put(OperationBlacklist, key, nil, epoch, ttl, now)
}
func (s *LocalState) Blacklisted(key string, epoch uint64, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	for _, e := range s.entries {
		if e.op == OperationBlacklist && e.key == key && e.epoch == epoch {
			return true, nil
		}
	}
	return false, nil
}
func (s *LocalState) PutCache(key string, value []byte, epoch uint64, ttl time.Duration, now time.Time) error {
	return s.put(OperationCache, key, value, epoch, ttl, now)
}
func (s *LocalState) put(op Operation, key string, value []byte, epoch uint64, ttl time.Duration, now time.Time) error {
	if key == "" || epoch == 0 || ttl <= 0 || s.policy.MaxLocalTTL <= 0 || ttl > s.policy.MaxLocalTTL {
		return ErrInvalidLease
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	entryKey := localKey{op: op, key: key}
	if _, exists := s.entries[entryKey]; !exists && len(s.entries) >= s.policy.MaxLocalEntries {
		return ErrLocalCapacity
	}
	s.entries[entryKey] = localEntry{op: op, key: key, epoch: epoch, value: append([]byte(nil), value...), expiresAt: now.Add(ttl)}
	return nil
}
func (s *LocalState) GetCache(key string, epoch uint64, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	e, ok := s.entries[localKey{op: OperationCache, key: key}]
	if !ok || e.epoch != epoch {
		return nil, false
	}
	return append([]byte(nil), e.value...), true
}
