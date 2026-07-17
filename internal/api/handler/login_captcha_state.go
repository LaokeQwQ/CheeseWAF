package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

const (
	loginCAPTCHAProofCapacity           = 4096
	loginCAPTCHAReceiptCapacity         = 4096
	loginCAPTCHAProofPerClient          = 16
	loginCAPTCHAReceiptPerClient        = 4
	loginCAPTCHAProofPerPeer            = 256
	loginCAPTCHAReceiptPerPeer          = 64
	loginCAPTCHAIssueConcurrentCapacity = 32
	loginCAPTCHAIssueConcurrentPerOwner = 1
	loginCAPTCHAIssueConcurrentPerPeer  = 8
	loginCAPTCHAIssueRateCapacity       = loginCAPTCHAProofCapacity
	loginCAPTCHAIssueRatePerOwner       = loginCAPTCHAProofPerClient
	loginCAPTCHAIssueRatePerPeer        = loginCAPTCHAProofPerPeer
	loginCAPTCHAIssueRateWindow         = time.Minute
	loginCAPTCHAIssueReservationTTL     = 30 * time.Second
	loginCAPTCHAPruneInterval           = 15 * time.Second
	loginRateLimitMaxFailures           = 5
	loginRateLimitWindow                = 5 * time.Minute
	loginRateLimitLockDuration          = 5 * time.Minute
	loginMaxConcurrentAttempts          = 32
)

type loginCAPTCHAState struct {
	mu            sync.Mutex
	proofs        map[string]loginCAPTCHAProofState
	receipts      map[string]loginCAPTCHAReceiptState
	loginFailures map[string]loginFailureState
	loginSlots    chan struct{}
	issuance      loginCAPTCHAIssuanceState
	nextPrune     time.Time
}

// AuthState groups ephemeral authentication state so multiple handlers can
// share one lifecycle. A distributed implementation can be introduced later
// without coupling the API package to a specific backend.
type AuthState struct {
	login *loginCAPTCHAState
	twoFA *twoFAState
}

func NewAuthState() *AuthState {
	return &AuthState{login: newLoginCAPTCHAState(), twoFA: newTwoFAState()}
}

func ApplyAuthState(h *Handler, state *AuthState) {
	if h == nil || state == nil {
		return
	}
	if state.login == nil {
		state.login = newLoginCAPTCHAState()
	}
	if state.twoFA == nil {
		state.twoFA = newTwoFAState()
	}
	h.LoginCAPTCHAState = state.login
	h.TwoFAState = state.twoFA
}

type loginCAPTCHAProofState struct {
	Owner   string
	Peer    string
	Status  loginCAPTCHAProofStatus
	Expires time.Time
	IssueID uint64
}

type loginCAPTCHAReceiptState struct {
	Owner   string
	Peer    string
	Expires time.Time
}

type loginCAPTCHAProofStatus uint8

const (
	loginCAPTCHAProofPending loginCAPTCHAProofStatus = iota
	loginCAPTCHAProofVerifying
	loginCAPTCHAProofUsed
)

type loginFailureState struct {
	Failures  int
	WindowEnd time.Time
	LockedTil time.Time
}

type loginCAPTCHAIssuanceLimits struct {
	concurrentGlobal int
	concurrentOwner  int
	concurrentPeer   int
	rateGlobal       int
	rateOwner        int
	ratePeer         int
	rateWindow       time.Duration
	reservationTTL   time.Duration
}

type loginCAPTCHAIssuanceState struct {
	limits          loginCAPTCHAIssuanceLimits
	reservations    map[uint64]*loginCAPTCHAIssuanceReservation
	ownerReserved   map[string]int
	peerReserved    map[string]int
	rates           map[uint64]loginCAPTCHAIssuanceRate
	ownerRate       map[string]int
	peerRate        map[string]int
	nextReservation uint64
}

type loginCAPTCHAIssuanceReservation struct {
	id             uint64
	owner          string
	peer           string
	expires        time.Time
	proofSlots     int
	staged         bool
	proofKeys      []string
	replacedProofs map[string]loginCAPTCHAProofState
	capacityGlobal int
	capacityPeer   int
}

type loginCAPTCHAIssuanceRate struct {
	owner     string
	peer      string
	expires   time.Time
	committed bool
}

func newLoginCAPTCHAState() *loginCAPTCHAState {
	return &loginCAPTCHAState{
		proofs:        map[string]loginCAPTCHAProofState{},
		receipts:      map[string]loginCAPTCHAReceiptState{},
		loginFailures: map[string]loginFailureState{},
		loginSlots:    make(chan struct{}, loginMaxConcurrentAttempts),
		issuance:      newLoginCAPTCHAIssuanceState(),
	}
}

func newLoginCAPTCHAIssuanceState() loginCAPTCHAIssuanceState {
	return loginCAPTCHAIssuanceState{
		limits: loginCAPTCHAIssuanceLimits{
			concurrentGlobal: loginCAPTCHAIssueConcurrentCapacity,
			concurrentOwner:  loginCAPTCHAIssueConcurrentPerOwner,
			concurrentPeer:   loginCAPTCHAIssueConcurrentPerPeer,
			rateGlobal:       loginCAPTCHAIssueRateCapacity,
			rateOwner:        loginCAPTCHAIssueRatePerOwner,
			ratePeer:         loginCAPTCHAIssueRatePerPeer,
			rateWindow:       loginCAPTCHAIssueRateWindow,
			reservationTTL:   loginCAPTCHAIssueReservationTTL,
		},
		reservations:  make(map[uint64]*loginCAPTCHAIssuanceReservation),
		ownerReserved: make(map[string]int),
		peerReserved:  make(map[string]int),
		rates:         make(map[uint64]loginCAPTCHAIssuanceRate),
		ownerRate:     make(map[string]int),
		peerRate:      make(map[string]int),
	}
}

func (s *loginCAPTCHAState) acquireLoginSlot() bool {
	if s == nil || s.loginSlots == nil {
		return false
	}
	select {
	case s.loginSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *loginCAPTCHAState) releaseLoginSlot() {
	if s == nil || s.loginSlots == nil {
		return
	}
	select {
	case <-s.loginSlots:
	default:
	}
}

func (h *Handler) loginCAPTCHATracker() *loginCAPTCHAState {
	if h.LoginCAPTCHAState == nil {
		h.LoginCAPTCHAState = newLoginCAPTCHAState()
	}
	return h.LoginCAPTCHAState
}

func (s *loginCAPTCHAState) registerProofs(keys []string, expires time.Time, now time.Time) bool {
	owner := "legacy"
	if len(keys) > 0 {
		owner = "legacy:" + keys[0]
	}
	return s.registerProofsForClient(owner, owner, keys, expires, now)
}

func (s *loginCAPTCHAState) registerProofsForClient(owner, peer string, keys []string, expires time.Time, now time.Time) bool {
	owner = strings.TrimSpace(owner)
	peer = strings.TrimSpace(peer)
	if s == nil || owner == "" || peer == "" || len(keys) == 0 || len(keys) > loginCAPTCHAProofPerClient || !expires.After(now) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	for key, state := range s.proofs {
		if state.Owner == owner && state.Status != loginCAPTCHAProofVerifying {
			delete(s.proofs, key)
		}
	}
	unique := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			return false
		}
		unique[key] = struct{}{}
	}
	additional := 0
	for key := range unique {
		if _, exists := s.proofs[key]; !exists {
			additional++
		}
	}
	peerCount := 0
	for _, state := range s.proofs {
		if state.Peer == peer {
			peerCount++
		}
	}
	if peerCount+additional > loginCAPTCHAProofPerPeer {
		return false
	}
	if len(s.proofs)+additional > loginCAPTCHAProofCapacity {
		s.pruneLocked(now)
		if len(s.proofs)+additional > loginCAPTCHAProofCapacity {
			return false
		}
	}
	for key := range unique {
		s.proofs[key] = loginCAPTCHAProofState{Owner: owner, Peer: peer, Status: loginCAPTCHAProofPending, Expires: expires}
	}
	return true
}

func (s *loginCAPTCHAState) reserveIssuance(owner, peer string, proofSlots int, now time.Time) (uint64, bool) {
	owner = strings.TrimSpace(owner)
	peer = strings.TrimSpace(peer)
	if s == nil || owner == "" || peer == "" || proofSlots < 1 || proofSlots > loginCAPTCHAProofPerClient {
		return 0, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	s.pruneExpiredIssuanceReservationsLocked(now)

	state := &s.issuance
	limits := state.limits
	if limits.concurrentGlobal < 1 || limits.concurrentOwner < 1 || limits.concurrentPeer < 1 ||
		limits.rateGlobal < 1 || limits.rateOwner < 1 || limits.ratePeer < 1 ||
		limits.rateWindow <= 0 || limits.reservationTTL <= 0 {
		return 0, false
	}
	if len(state.rates) >= limits.rateGlobal || state.ownerRate[owner] >= limits.rateOwner || state.peerRate[peer] >= limits.ratePeer {
		s.pruneExpiredIssuanceRatesLocked(now)
	}
	if len(state.reservations) >= limits.concurrentGlobal || state.ownerReserved[owner] >= limits.concurrentOwner ||
		state.peerReserved[peer] >= limits.concurrentPeer || len(state.rates) >= limits.rateGlobal ||
		state.ownerRate[owner] >= limits.rateOwner || state.peerRate[peer] >= limits.ratePeer {
		return 0, false
	}

	replaceable, replaceableAtPeer, peerProofs := 0, 0, 0
	for _, proof := range s.proofs {
		if proof.Peer == peer {
			peerProofs++
		}
		if proof.Owner != owner || proof.Status == loginCAPTCHAProofVerifying {
			continue
		}
		replaceable++
		if proof.Peer == peer {
			replaceableAtPeer++
		}
	}
	capacityGlobal := proofSlots - replaceable
	if capacityGlobal < 0 {
		capacityGlobal = 0
	}
	capacityPeer := proofSlots - replaceableAtPeer
	if capacityPeer < 0 {
		capacityPeer = 0
	}
	reservedGlobal, reservedPeer := s.reservedIssuanceCapacityLocked(0, peer)
	if len(s.proofs)+reservedGlobal+capacityGlobal > loginCAPTCHAProofCapacity ||
		peerProofs+reservedPeer+capacityPeer > loginCAPTCHAProofPerPeer {
		return 0, false
	}

	var id uint64
	for {
		state.nextReservation++
		id = state.nextReservation
		if id == 0 {
			continue
		}
		if _, reserved := state.reservations[id]; reserved {
			continue
		}
		if _, rateExists := state.rates[id]; !rateExists {
			break
		}
	}
	state.reservations[id] = &loginCAPTCHAIssuanceReservation{
		id:             id,
		owner:          owner,
		peer:           peer,
		expires:        now.Add(limits.reservationTTL),
		proofSlots:     proofSlots,
		capacityGlobal: capacityGlobal,
		capacityPeer:   capacityPeer,
	}
	state.ownerReserved[owner]++
	state.peerReserved[peer]++
	state.rates[id] = loginCAPTCHAIssuanceRate{owner: owner, peer: peer, expires: now.Add(limits.rateWindow)}
	state.ownerRate[owner]++
	state.peerRate[peer]++
	return id, true
}

func (s *loginCAPTCHAState) stageIssuance(id uint64, keys []string, expires, now time.Time) bool {
	if s == nil || id == 0 || len(keys) == 0 || !expires.After(now) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)

	reservation, ok := s.issuance.reservations[id]
	if !ok || reservation.staged || !reservation.expires.After(now) || len(keys) != reservation.proofSlots {
		if ok && !reservation.staged && !reservation.expires.After(now) {
			s.rollbackIssuanceLocked(id)
		}
		return false
	}
	if _, ok = s.issuance.rates[id]; !ok {
		return false
	}
	unique := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key = strings.TrimSpace(key); key == "" {
			return false
		}
		unique[key] = struct{}{}
	}
	if len(unique) != reservation.proofSlots {
		return false
	}

	ownerProofs, replaceable, peerProofs, replaceableAtPeer := 0, 0, 0, 0
	for _, proof := range s.proofs {
		if proof.Peer == reservation.peer {
			peerProofs++
		}
		if proof.Owner != reservation.owner {
			continue
		}
		ownerProofs++
		if proof.Status == loginCAPTCHAProofVerifying {
			continue
		}
		replaceable++
		if proof.Peer == reservation.peer {
			replaceableAtPeer++
		}
	}
	reservedGlobal, reservedPeer := s.reservedIssuanceCapacityLocked(id, reservation.peer)
	if ownerProofs-replaceable+reservation.proofSlots > loginCAPTCHAProofPerClient ||
		len(s.proofs)-replaceable+reservation.proofSlots+reservedGlobal > loginCAPTCHAProofCapacity ||
		peerProofs-replaceableAtPeer+reservation.proofSlots+reservedPeer > loginCAPTCHAProofPerPeer {
		return false
	}

	replaced := make(map[string]loginCAPTCHAProofState)
	for key, proof := range s.proofs {
		if proof.Owner == reservation.owner && proof.Status != loginCAPTCHAProofVerifying {
			replaced[key] = proof
			delete(s.proofs, key)
		}
	}
	for key := range unique {
		s.proofs[key] = loginCAPTCHAProofState{
			Owner: reservation.owner, Peer: reservation.peer, Status: loginCAPTCHAProofPending,
			Expires: expires, IssueID: id,
		}
	}
	reservation.staged = true
	reservation.proofKeys = append(reservation.proofKeys[:0], keys...)
	reservation.replacedProofs = replaced
	return true
}

func (s *loginCAPTCHAState) finalizeIssuance(id uint64) bool {
	if s == nil || id == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation, ok := s.issuance.reservations[id]
	if !ok || !reservation.staged {
		return false
	}
	rate, ok := s.issuance.rates[id]
	if !ok {
		return false
	}
	rate.committed = true
	s.issuance.rates[id] = rate
	reservation.proofKeys = nil
	reservation.replacedProofs = nil
	s.releaseIssuanceReservationLocked(id, true)
	return true
}

func (s *loginCAPTCHAState) rollbackIssuance(id uint64) {
	if s == nil || id == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollbackIssuanceLocked(id)
}

func (s *loginCAPTCHAState) reservedIssuanceCapacityLocked(excludeID uint64, peer string) (int, int) {
	global, peerCapacity := 0, 0
	for id, reservation := range s.issuance.reservations {
		if id == excludeID || reservation.staged {
			continue
		}
		global += reservation.capacityGlobal
		if reservation.peer == peer {
			peerCapacity += reservation.capacityPeer
		}
	}
	return global, peerCapacity
}

func (s *loginCAPTCHAState) releaseIssuanceReservationLocked(id uint64, keepRate bool) {
	reservation, ok := s.issuance.reservations[id]
	if !ok {
		return
	}
	delete(s.issuance.reservations, id)
	decrementLoginCAPTCHACounter(s.issuance.ownerReserved, reservation.owner)
	decrementLoginCAPTCHACounter(s.issuance.peerReserved, reservation.peer)
	if !keepRate {
		s.removeIssuanceRateLocked(id)
	}
}

func (s *loginCAPTCHAState) rollbackIssuanceLocked(id uint64) {
	reservation, ok := s.issuance.reservations[id]
	if !ok {
		return
	}
	if reservation.staged {
		for _, key := range reservation.proofKeys {
			proof, exists := s.proofs[key]
			if exists && proof.IssueID == id {
				delete(s.proofs, key)
			}
		}
		for key, proof := range reservation.replacedProofs {
			if _, exists := s.proofs[key]; !exists {
				s.proofs[key] = proof
			}
		}
	}
	s.releaseIssuanceReservationLocked(id, false)
}

func (s *loginCAPTCHAState) removeIssuanceRateLocked(id uint64) {
	rate, ok := s.issuance.rates[id]
	if !ok {
		return
	}
	delete(s.issuance.rates, id)
	decrementLoginCAPTCHACounter(s.issuance.ownerRate, rate.owner)
	decrementLoginCAPTCHACounter(s.issuance.peerRate, rate.peer)
}

func (s *loginCAPTCHAState) pruneExpiredIssuanceReservationsLocked(now time.Time) {
	for id, reservation := range s.issuance.reservations {
		if !reservation.staged && !reservation.expires.After(now) {
			s.rollbackIssuanceLocked(id)
		}
	}
}

func (s *loginCAPTCHAState) pruneExpiredIssuanceRatesLocked(now time.Time) {
	for id, rate := range s.issuance.rates {
		if rate.expires.After(now) {
			continue
		}
		if reservation, reserved := s.issuance.reservations[id]; reserved {
			if reservation.staged {
				continue
			}
			s.rollbackIssuanceLocked(id)
			continue
		}
		s.removeIssuanceRateLocked(id)
	}
}

func decrementLoginCAPTCHACounter(counts map[string]int, key string) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key]--
}

func (s *loginCAPTCHAState) reserveProofs(keys []string, now time.Time) bool {
	if s == nil || len(keys) == 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	unique := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		state, exists := s.proofs[key]
		if key == "" || !exists || !state.Expires.After(now) || state.Status != loginCAPTCHAProofPending {
			return false
		}
		unique[key] = struct{}{}
	}
	for key := range unique {
		state := s.proofs[key]
		state.Status = loginCAPTCHAProofVerifying
		s.proofs[key] = state
	}
	return true
}

func (s *loginCAPTCHAState) finishProofs(keys []string, _ bool, now time.Time) {
	if s == nil || len(keys) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	for _, key := range keys {
		state, exists := s.proofs[key]
		if !exists || state.Status != loginCAPTCHAProofVerifying {
			continue
		}
		state.Status = loginCAPTCHAProofUsed
		s.proofs[key] = state
	}
}

func (s *loginCAPTCHAState) storeReceipt(receipt string, expires time.Time, now time.Time) bool {
	owner := "legacy:" + loginCAPTCHAFingerprint(receipt)
	return s.storeReceiptForClient(owner, owner, receipt, expires, now)
}

func (s *loginCAPTCHAState) storeReceiptForClient(owner, peer, receipt string, expires time.Time, now time.Time) bool {
	owner = strings.TrimSpace(owner)
	peer = strings.TrimSpace(peer)
	if s == nil || owner == "" || peer == "" || receipt == "" || !expires.After(now) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	ownerCount := 0
	for key, state := range s.receipts {
		if state.Owner == owner {
			ownerCount++
			if ownerCount >= loginCAPTCHAReceiptPerClient {
				delete(s.receipts, key)
			}
		}
	}
	peerCount := 0
	for _, state := range s.receipts {
		if state.Peer == peer {
			peerCount++
		}
	}
	if peerCount >= loginCAPTCHAReceiptPerPeer {
		return false
	}
	if len(s.receipts) >= loginCAPTCHAReceiptCapacity {
		s.pruneLocked(now)
		if len(s.receipts) >= loginCAPTCHAReceiptCapacity {
			return false
		}
	}
	s.receipts[loginCAPTCHAFingerprint(receipt)] = loginCAPTCHAReceiptState{Owner: owner, Peer: peer, Expires: expires}
	return true
}

func (s *loginCAPTCHAState) consumeReceiptForClient(owner, peer, receipt string, now time.Time) bool {
	owner = strings.TrimSpace(owner)
	peer = strings.TrimSpace(peer)
	if s == nil || owner == "" || peer == "" || receipt == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	key := loginCAPTCHAFingerprint(receipt)
	state, ok := s.receipts[key]
	if !ok || !state.Expires.After(now) {
		delete(s.receipts, key)
		return false
	}
	if state.Owner != owner || state.Peer != peer {
		return false
	}
	delete(s.receipts, key)
	return true
}

func (s *loginCAPTCHAState) loginAttemptAllowed(keys []string, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	for _, key := range keys {
		if !loginFailureKeyAllowed(key) {
			continue
		}
		state := s.loginFailures[key]
		if state.LockedTil.After(now) {
			return false
		}
	}
	return true
}

func (s *loginCAPTCHAState) recordLoginFailure(keys []string, now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	for _, key := range keys {
		if !loginFailureKeyAllowed(key) {
			continue
		}
		state := s.loginFailures[key]
		if state.WindowEnd.IsZero() || !state.WindowEnd.After(now) {
			state = loginFailureState{WindowEnd: now.Add(loginRateLimitWindow)}
		}
		state.Failures++
		if state.Failures >= loginRateLimitMaxFailures {
			state.LockedTil = now.Add(loginRateLimitLockDuration)
		}
		s.loginFailures[key] = state
	}
}

func (s *loginCAPTCHAState) clearLoginFailures(keys []string, now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybePruneLocked(now)
	for _, key := range keys {
		if !loginFailureKeyAllowed(key) {
			continue
		}
		delete(s.loginFailures, key)
	}
}

func loginFailureKeyAllowed(key string) bool {
	return key != "" && !strings.HasPrefix(key, "user:")
}

func (s *loginCAPTCHAState) pruneLocked(now time.Time) {
	s.pruneExpiredIssuanceReservationsLocked(now)
	s.pruneExpiredIssuanceRatesLocked(now)
	for key, state := range s.proofs {
		if !state.Expires.IsZero() && !state.Expires.After(now) {
			delete(s.proofs, key)
		}
	}
	for key, state := range s.receipts {
		if !state.Expires.After(now) {
			delete(s.receipts, key)
		}
	}
	for key, state := range s.loginFailures {
		if !state.LockedTil.After(now) && !state.WindowEnd.After(now) {
			delete(s.loginFailures, key)
		}
	}
}

func (s *loginCAPTCHAState) maybePruneLocked(now time.Time) {
	if s.nextPrune.After(now) {
		return
	}
	s.pruneLocked(now)
	s.nextPrune = now.Add(loginCAPTCHAPruneInterval)
}

func loginCAPTCHAFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}
