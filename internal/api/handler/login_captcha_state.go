package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

const loginCAPTCHAMaxFailures = 5

type loginCAPTCHAState struct {
	mu       sync.Mutex
	proofs   map[string]loginCAPTCHAProofState
	receipts map[string]time.Time
}

type loginCAPTCHAProofState struct {
	Failures int
	Used     bool
	Expires  time.Time
}

func newLoginCAPTCHAState() *loginCAPTCHAState {
	return &loginCAPTCHAState{
		proofs:   map[string]loginCAPTCHAProofState{},
		receipts: map[string]time.Time{},
	}
}

func (h *Handler) loginCAPTCHATracker() *loginCAPTCHAState {
	if h.LoginCAPTCHAState == nil {
		h.LoginCAPTCHAState = newLoginCAPTCHAState()
	}
	return h.LoginCAPTCHAState
}

func (s *loginCAPTCHAState) proofAllowed(key string, now time.Time) bool {
	if s == nil || key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	state := s.proofs[key]
	return !state.Used && state.Failures < loginCAPTCHAMaxFailures
}

func (s *loginCAPTCHAState) recordProofFailure(key string, expires time.Time, now time.Time) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	state := s.proofs[key]
	state.Failures++
	state.Expires = expires
	s.proofs[key] = state
}

func (s *loginCAPTCHAState) markProofUsed(key string, expires time.Time, now time.Time) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.proofs[key] = loginCAPTCHAProofState{Used: true, Expires: expires}
}

func (s *loginCAPTCHAState) storeReceipt(receipt string, expires time.Time, now time.Time) {
	if s == nil || receipt == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.receipts[loginCAPTCHAFingerprint(receipt)] = expires
}

func (s *loginCAPTCHAState) consumeReceipt(receipt string, now time.Time) bool {
	if s == nil || receipt == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	key := loginCAPTCHAFingerprint(receipt)
	expires, ok := s.receipts[key]
	if !ok || !expires.After(now) {
		delete(s.receipts, key)
		return false
	}
	delete(s.receipts, key)
	return true
}

func (s *loginCAPTCHAState) pruneLocked(now time.Time) {
	for key, state := range s.proofs {
		if !state.Expires.IsZero() && !state.Expires.After(now) {
			delete(s.proofs, key)
		}
	}
	for key, expires := range s.receipts {
		if !expires.After(now) {
			delete(s.receipts, key)
		}
	}
}

func loginCAPTCHAFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
