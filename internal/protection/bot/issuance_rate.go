package bot

import (
	"container/heap"
	"time"
)

const (
	issuanceRateCleanupBudget = 64
	generationReservationTTL  = 15 * time.Second
)

func generationReservationExpiry(now, requested time.Time) time.Time {
	leaseExpiry := now.Add(generationReservationTTL)
	if requested.Before(leaseExpiry) {
		return requested
	}
	return leaseExpiry
}

type issuanceRateExpiry struct {
	id      uint64
	expires time.Time
	index   int
}

type issuanceRateExpiryHeap []*issuanceRateExpiry

func (h issuanceRateExpiryHeap) Len() int           { return len(h) }
func (h issuanceRateExpiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h issuanceRateExpiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *issuanceRateExpiryHeap) Push(value any) {
	item := value.(*issuanceRateExpiry)
	item.index = len(*h)
	*h = append(*h, item)
}
func (h *issuanceRateExpiryHeap) Pop() any {
	old := *h
	last := len(old) - 1
	item := old[last]
	old[last] = nil
	item.index = -1
	*h = old[:last]
	return item
}

type issuanceRateRecord struct {
	owner, peer string
	expiry      *issuanceRateExpiry
	committed   bool
}

type issuanceRateState struct {
	window                             time.Duration
	globalLimit, ownerLimit, peerLimit int
	records                            map[uint64]issuanceRateRecord
	ownerCount, peerCount              map[string]int
	expirations                        issuanceRateExpiryHeap
	nextID                             uint64
}

func newIssuanceRateState(window time.Duration, globalLimit, ownerLimit, peerLimit int) *issuanceRateState {
	if window <= 0 || globalLimit < 1 || ownerLimit < 1 || peerLimit < 1 {
		return nil
	}
	return &issuanceRateState{
		window:      window,
		globalLimit: globalLimit,
		ownerLimit:  min(ownerLimit, globalLimit),
		peerLimit:   min(peerLimit, globalLimit),
		records:     make(map[uint64]issuanceRateRecord),
		ownerCount:  make(map[string]int),
		peerCount:   make(map[string]int),
	}
}

func (s *issuanceRateState) reserve(now time.Time, owner, peer string) (uint64, error) {
	if s == nil {
		return 0, nil
	}
	s.clean(now, issuanceRateCleanupBudget)
	if len(s.records) >= s.globalLimit || s.ownerCount[owner] >= s.ownerLimit || s.peerCount[peer] >= s.peerLimit {
		return 0, ErrChallengeCapacity
	}
	s.nextID++
	if s.nextID == 0 {
		s.nextID++
	}
	id := s.nextID
	expiry := &issuanceRateExpiry{id: id, expires: now.Add(s.window)}
	s.records[id] = issuanceRateRecord{owner: owner, peer: peer, expiry: expiry}
	s.ownerCount[owner]++
	s.peerCount[peer]++
	heap.Push(&s.expirations, expiry)
	return id, nil
}

func (s *issuanceRateState) start(id uint64) bool {
	if s == nil {
		return true
	}
	record, ok := s.records[id]
	if !ok || record.committed {
		return false
	}
	record.committed = true
	s.records[id] = record
	return true
}

func (s *issuanceRateState) started(id uint64) bool {
	if s == nil {
		return true
	}
	record, ok := s.records[id]
	return ok && record.committed
}

func (s *issuanceRateState) rollback(id uint64) bool {
	if s == nil {
		return true
	}
	record, ok := s.records[id]
	if !ok || record.committed {
		return false
	}
	s.remove(id, record)
	return true
}

func (s *issuanceRateState) clean(now time.Time, budget int) int {
	if s == nil || budget < 1 {
		return 0
	}
	cleaned := 0
	for len(s.expirations) > 0 && cleaned < budget {
		next := s.expirations[0]
		if now.Before(next.expires) {
			break
		}
		heap.Pop(&s.expirations)
		record, ok := s.records[next.id]
		if ok && record.expiry == next {
			s.removeEntry(next.id, record)
		}
		cleaned++
	}
	return cleaned
}

func (s *issuanceRateState) remove(id uint64, record issuanceRateRecord) {
	if record.expiry != nil && record.expiry.index >= 0 {
		heap.Remove(&s.expirations, record.expiry.index)
	}
	s.removeEntry(id, record)
}

func (s *issuanceRateState) removeEntry(id uint64, record issuanceRateRecord) {
	delete(s.records, id)
	decrementIssueCount(s.ownerCount, record.owner)
	decrementIssueCount(s.peerCount, record.peer)
}

func decrementIssueCount(counts map[string]int, key string) {
	if remaining := counts[key] - 1; remaining > 0 {
		counts[key] = remaining
	} else {
		delete(counts, key)
	}
}
