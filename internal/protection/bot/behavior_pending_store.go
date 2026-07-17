package bot

import (
	"container/heap"
	"errors"
	"sync"
	"time"
)

const (
	defaultBehaviorPendingCapacity      = 10000
	defaultBehaviorPendingPerOwner      = 8
	behaviorPendingCleanupOperationMask = 63
	behaviorPendingCleanupBudget        = 64
	behaviorIssueRateWindow             = time.Minute
	behaviorIssueRateMultiplier         = 4
)

type behaviorPendingExpiry struct {
	jti     string
	expires time.Time
	index   int
}

type behaviorPendingExpiryHeap []*behaviorPendingExpiry

func (h behaviorPendingExpiryHeap) Len() int           { return len(h) }
func (h behaviorPendingExpiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h behaviorPendingExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *behaviorPendingExpiryHeap) Push(value any) {
	item := value.(*behaviorPendingExpiry)
	item.index = len(*h)
	*h = append(*h, item)
}
func (h *behaviorPendingExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	value := old[last]
	old[last] = nil
	value.index = -1
	*h = old[:last]
	return value
}

type behaviorPendingEntry struct {
	pending behaviorPending
	expiry  *behaviorPendingExpiry
	claimed bool
}

type behaviorPendingReservation struct {
	id, rateID  uint64
	owner, peer string
	expires     time.Time
}

// behaviorPendingStore owns the complete lifecycle of an issued behavior
// challenge. Entries can only move from pending to consumed or expired.
type behaviorPendingStore struct {
	mu                 sync.Mutex
	entries            map[string]behaviorPendingEntry
	ownerPending       map[string]int
	peerPending        map[string]int
	reservations       map[uint64]*behaviorPendingReservation
	ownerReserved      map[string]int
	peerReserved       map[string]int
	expirations        behaviorPendingExpiryHeap
	capacity           int
	perOwnerCapacity   int
	perPeerCapacity    int
	concurrentCapacity int
	perOwnerConcurrent int
	perPeerConcurrent  int
	rates              *issuanceRateState
	now                func() time.Time
	operations         uint64
	nextReservation    uint64
}

func newBehaviorPendingStore(capacity, perOwnerCapacity int, now func() time.Time) *behaviorPendingStore {
	if capacity < 1 {
		capacity = defaultBehaviorPendingCapacity
	}
	if perOwnerCapacity < 1 {
		perOwnerCapacity = defaultBehaviorPendingPerOwner
	}
	if perOwnerCapacity > capacity {
		perOwnerCapacity = capacity
	}
	if now == nil {
		now = time.Now
	}
	perPeerCapacity := min(capacity, perOwnerCapacity*4)
	return &behaviorPendingStore{
		entries:            make(map[string]behaviorPendingEntry),
		ownerPending:       make(map[string]int),
		peerPending:        make(map[string]int),
		reservations:       make(map[uint64]*behaviorPendingReservation),
		ownerReserved:      make(map[string]int),
		peerReserved:       make(map[string]int),
		capacity:           capacity,
		perOwnerCapacity:   perOwnerCapacity,
		perPeerCapacity:    perPeerCapacity,
		concurrentCapacity: min(capacity, 64),
		perOwnerConcurrent: min(perOwnerCapacity, 2),
		perPeerConcurrent:  min(perPeerCapacity, 8),
		rates: newIssuanceRateState(
			behaviorIssueRateWindow,
			capacity*behaviorIssueRateMultiplier,
			perOwnerCapacity*behaviorIssueRateMultiplier,
			perPeerCapacity*behaviorIssueRateMultiplier,
		),
		now: now,
	}
}

func (s *behaviorPendingStore) Add(jti string, pending behaviorPending) error {
	if s == nil || jti == "" || pending.owner == "" || pending.peer == "" || pending.expires.IsZero() {
		return errors.New("behavior challenge identity, owner, peer, and expiration required")
	}
	reservation, err := s.Reserve(pending.owner, pending.peer, pending.expires)
	if err != nil {
		return err
	}
	if err = s.Start(reservation); err != nil {
		s.Rollback(reservation)
		return err
	}
	if err = s.Commit(reservation, jti, pending); err != nil {
		s.Rollback(reservation)
		return err
	}
	return nil
}

func (s *behaviorPendingStore) Reserve(owner, peer string, expires time.Time) (*behaviorPendingReservation, error) {
	if s == nil || owner == "" || peer == "" || expires.IsZero() {
		return nil, errors.New("behavior challenge owner, peer, and expiration required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.cleanExpiredLocked(now, behaviorPendingCleanupBudget)
	s.cleanReservationsLocked(now, behaviorPendingCleanupBudget)
	if s.rates != nil {
		s.rates.clean(now, issuanceRateCleanupBudget)
	}
	if !now.Before(expires) {
		return nil, errors.New("behavior challenge already expired")
	}
	if len(s.entries)+len(s.reservations) >= s.capacity ||
		s.ownerPending[owner]+s.ownerReserved[owner] >= s.perOwnerCapacity ||
		s.peerPending[peer]+s.peerReserved[peer] >= s.perPeerCapacity ||
		len(s.reservations) >= s.concurrentCapacity ||
		s.ownerReserved[owner] >= s.perOwnerConcurrent ||
		s.peerReserved[peer] >= s.perPeerConcurrent {
		return nil, ErrChallengeCapacity
	}
	rateID, err := s.rates.reserve(now, owner, peer)
	if err != nil {
		return nil, err
	}
	s.nextReservation++
	if s.nextReservation == 0 {
		s.nextReservation++
	}
	reservation := &behaviorPendingReservation{id: s.nextReservation, rateID: rateID, owner: owner, peer: peer, expires: generationReservationExpiry(now, expires)}
	s.reservations[reservation.id] = reservation
	s.ownerReserved[owner]++
	s.peerReserved[peer]++
	return reservation, nil
}

func (s *behaviorPendingStore) Start(reservation *behaviorPendingReservation) error {
	if s == nil || reservation == nil {
		return errors.New("behavior challenge reservation required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.reservations[reservation.id]
	if !ok || stored != reservation || !s.now().Before(reservation.expires) {
		return errors.New("behavior challenge reservation is stale")
	}
	if !s.rates.start(reservation.rateID) {
		return errors.New("behavior challenge rate reservation is stale")
	}
	return nil
}

func (s *behaviorPendingStore) Commit(reservation *behaviorPendingReservation, jti string, pending behaviorPending) error {
	if s == nil || reservation == nil || jti == "" {
		return errors.New("behavior challenge reservation and identity required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.reservations[reservation.id]
	if !ok || stored != reservation {
		return errors.New("behavior challenge reservation is stale")
	}
	now := s.now()
	if !now.Before(reservation.expires) || !now.Before(pending.expires) || pending.owner != reservation.owner || pending.peer != reservation.peer {
		s.rollbackReservationLocked(reservation)
		return errors.New("behavior challenge reservation does not match pending challenge")
	}
	if _, exists := s.entries[jti]; exists {
		s.rollbackReservationLocked(reservation)
		return errors.New("duplicate behavior challenge")
	}
	if !s.rates.started(reservation.rateID) {
		s.rollbackReservationLocked(reservation)
		return errors.New("behavior challenge work was not started")
	}
	s.removeReservationLocked(reservation)
	expiry := &behaviorPendingExpiry{jti: jti, expires: pending.expires}
	s.entries[jti] = behaviorPendingEntry{pending: pending, expiry: expiry}
	s.ownerPending[pending.owner]++
	s.peerPending[pending.peer]++
	heap.Push(&s.expirations, expiry)
	return nil
}

func (s *behaviorPendingStore) Rollback(reservation *behaviorPendingReservation) bool {
	if s == nil || reservation == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.reservations[reservation.id]
	if !ok || stored != reservation {
		return false
	}
	return s.rollbackReservationLocked(reservation)
}

func (s *behaviorPendingStore) Claim(jti, owner string) (behaviorPending, bool) {
	if s == nil || jti == "" {
		return behaviorPending{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.operations&behaviorPendingCleanupOperationMask == 0 {
		s.cleanExpiredLocked(now, behaviorPendingCleanupBudget)
		s.cleanReservationsLocked(now, behaviorPendingCleanupBudget)
		if s.rates != nil {
			s.rates.clean(now, issuanceRateCleanupBudget)
		}
	}
	s.operations++
	entry, ok := s.entries[jti]
	if !ok || entry.claimed || entry.pending.owner != owner || !now.Before(entry.pending.expires) {
		if ok {
			if !now.Before(entry.pending.expires) {
				s.deleteLocked(jti, entry)
			}
		}
		return behaviorPending{}, false
	}
	entry.claimed = true
	s.entries[jti] = entry
	return entry.pending, true
}

func (s *behaviorPendingStore) Finalize(jti string) bool {
	return s.removeClaimed(jti, false)
}

func (s *behaviorPendingStore) Release(jti string) bool {
	if s == nil || jti == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[jti]
	if !ok || !entry.claimed || !s.now().Before(entry.pending.expires) {
		if ok && !s.now().Before(entry.pending.expires) {
			s.deleteLocked(jti, entry)
		}
		return false
	}
	entry.claimed = false
	s.entries[jti] = entry
	return true
}

func (s *behaviorPendingStore) removeClaimed(jti string, allowUnclaimed bool) bool {
	if s == nil || jti == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[jti]
	if !ok || (!allowUnclaimed && !entry.claimed) {
		return false
	}
	s.deleteLocked(jti, entry)
	return true
}

func (s *behaviorPendingStore) Revoke(jti string) bool {
	return s.removeClaimed(jti, true)
}

func (s *behaviorPendingStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.cleanExpiredLocked(s.now(), behaviorPendingCleanupBudget) == behaviorPendingCleanupBudget {
	}
	now := s.now()
	for _, reservation := range s.reservations {
		if !now.Before(reservation.expires) {
			s.rollbackReservationLocked(reservation)
		}
	}
	if s.rates != nil {
		for s.rates.clean(now, issuanceRateCleanupBudget) == issuanceRateCleanupBudget {
		}
	}
	return len(s.entries)
}

func (s *behaviorPendingStore) cleanReservationsLocked(now time.Time, budget int) int {
	cleaned, inspected := 0, 0
	for _, reservation := range s.reservations {
		if inspected >= budget {
			break
		}
		inspected++
		if now.Before(reservation.expires) {
			continue
		}
		s.rollbackReservationLocked(reservation)
		cleaned++
	}
	return cleaned
}

func (s *behaviorPendingStore) rollbackReservationLocked(reservation *behaviorPendingReservation) bool {
	if reservation == nil || s.reservations[reservation.id] != reservation {
		return false
	}
	s.rates.rollback(reservation.rateID)
	s.removeReservationLocked(reservation)
	return true
}

func (s *behaviorPendingStore) removeReservationLocked(reservation *behaviorPendingReservation) {
	delete(s.reservations, reservation.id)
	decrementIssueCount(s.ownerReserved, reservation.owner)
	decrementIssueCount(s.peerReserved, reservation.peer)
}

func (s *behaviorPendingStore) cleanExpiredLocked(now time.Time, budget int) int {
	cleaned := 0
	for len(s.expirations) > 0 && cleaned < budget {
		next := s.expirations[0]
		if now.Before(next.expires) {
			break
		}
		heap.Pop(&s.expirations)
		entry, ok := s.entries[next.jti]
		if ok && entry.expiry == next {
			s.deleteEntryLocked(next.jti, entry.pending)
		}
		cleaned++
	}
	return cleaned
}

func (s *behaviorPendingStore) deleteLocked(jti string, entry behaviorPendingEntry) {
	if entry.expiry != nil && entry.expiry.index >= 0 {
		heap.Remove(&s.expirations, entry.expiry.index)
	}
	s.deleteEntryLocked(jti, entry.pending)
}

func (s *behaviorPendingStore) deleteEntryLocked(jti string, pending behaviorPending) {
	delete(s.entries, jti)
	if remaining := s.ownerPending[pending.owner] - 1; remaining > 0 {
		s.ownerPending[pending.owner] = remaining
	} else {
		delete(s.ownerPending, pending.owner)
	}
	if remaining := s.peerPending[pending.peer] - 1; remaining > 0 {
		s.peerPending[pending.peer] = remaining
	} else {
		delete(s.peerPending, pending.peer)
	}
}
