package assets

import (
	"container/heap"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	referenceGlobalCapacity = 8192
	referenceOwnerCapacity  = 128
	referenceMaxTokenBytes  = 4096
)

type ReferenceManager struct {
	secret []byte
	now    func() time.Time
	mu     sync.Mutex
	states map[string]referenceState
	owners map[string]int
	expiry referenceExpiryHeap
}
type referenceClaims struct {
	ID      string `json:"id"`
	Scope   string `json:"scope"`
	Expires int64  `json:"exp"`
	Nonce   string `json:"nonce"`
	Owner   string `json:"owner"`
}

type referenceState struct {
	owner       string
	expires     time.Time
	status      referenceStatus
	reservation string
}

type referenceStatus uint8

const (
	referencePending referenceStatus = iota
	referenceReserved
	referenceUsed
)

type ReferenceReservation struct {
	ID          string
	nonce       string
	reservation string
}

type referenceExpiry struct {
	nonce   string
	expires time.Time
}

type referenceExpiryHeap []referenceExpiry

func (h referenceExpiryHeap) Len() int           { return len(h) }
func (h referenceExpiryHeap) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h referenceExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *referenceExpiryHeap) Push(v any)        { *h = append(*h, v.(referenceExpiry)) }
func (h *referenceExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	v := old[n-1]
	*h = old[:n-1]
	return v
}

func NewReferenceManager(secret []byte) (*ReferenceManager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("reference secret must contain at least 32 bytes")
	}
	return &ReferenceManager{secret: append([]byte(nil), secret...), now: time.Now, states: map[string]referenceState{}, owners: map[string]int{}}, nil
}
func (m *ReferenceManager) Issue(id, scope string, ttl time.Duration) (string, error) {
	return m.IssueFor(id, scope, scope, ttl)
}

func (m *ReferenceManager) IssueFor(id, scope, owner string, ttl time.Duration) (string, error) {
	scope = strings.TrimSpace(scope)
	owner = strings.TrimSpace(owner)
	if !validID(id) || scope == "" || owner == "" || len(scope) > 128 || len(owner) > 256 || ttl <= 0 || ttl > 15*time.Minute {
		return "", fmt.Errorf("%w: invalid reference parameters", ErrInvalidAsset)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	now := m.now()
	expires := now.Add(ttl)
	nonceValue := base64.RawURLEncoding.EncodeToString(nonce)
	m.mu.Lock()
	m.pruneLocked(now)
	if len(m.states) >= referenceGlobalCapacity || m.owners[owner] >= referenceOwnerCapacity {
		m.mu.Unlock()
		return "", ErrReferenceCapacity
	}
	m.states[nonceValue] = referenceState{owner: owner, expires: expires}
	m.owners[owner]++
	heap.Push(&m.expiry, referenceExpiry{nonce: nonceValue, expires: expires})
	m.mu.Unlock()
	c := referenceClaims{ID: id, Scope: scope, Expires: expires.Unix(), Nonce: nonceValue, Owner: owner}
	payload, err := json.Marshal(c)
	if err != nil {
		m.removeState(nonceValue)
		return "", err
	}
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (m *ReferenceManager) Consume(token, scope string) (string, error) {
	reservation, err := m.Reserve(token, scope)
	if err != nil {
		return "", err
	}
	if err = m.Commit(reservation); err != nil {
		return "", err
	}
	return reservation.ID, nil
}

func (m *ReferenceManager) Reserve(token, scope string, expectedOwner ...string) (*ReferenceReservation, error) {
	if len(token) == 0 || len(token) > referenceMaxTokenBytes {
		return nil, ErrInvalidAsset
	}
	p, sig, ok := strings.Cut(token, ".")
	if !ok || p == "" || sig == "" {
		return nil, ErrInvalidAsset
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, ErrInvalidAsset
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, ErrInvalidAsset
	}
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return nil, ErrInvalidAsset
	}
	var c referenceClaims
	if json.Unmarshal(payload, &c) != nil || c.Scope != scope || strings.TrimSpace(c.Owner) == "" || !validID(c.ID) {
		return nil, ErrInvalidAsset
	}
	if len(expectedOwner) > 1 {
		return nil, ErrInvalidAsset
	}
	if len(expectedOwner) == 1 {
		owner := strings.TrimSpace(expectedOwner[0])
		if owner == "" || !hmac.Equal([]byte(c.Owner), []byte(owner)) {
			return nil, ErrInvalidAsset
		}
	}
	now := m.now()
	if now.Unix() >= c.Expires {
		return nil, ErrReferenceExpired
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	state, exists := m.states[c.Nonce]
	if !exists || state.owner != c.Owner || state.expires.Unix() != c.Expires {
		return nil, ErrInvalidAsset
	}
	if state.status != referencePending {
		return nil, ErrReferenceUsed
	}
	reservationBytes := make([]byte, 16)
	if _, err = rand.Read(reservationBytes); err != nil {
		return nil, err
	}
	reservationID := base64.RawURLEncoding.EncodeToString(reservationBytes)
	state.status = referenceReserved
	state.reservation = reservationID
	m.states[c.Nonce] = state
	return &ReferenceReservation{ID: c.ID, nonce: c.Nonce, reservation: reservationID}, nil
}

func (m *ReferenceManager) Commit(reservation *ReferenceReservation) error {
	if reservation == nil || reservation.nonce == "" || reservation.reservation == "" || !validID(reservation.ID) {
		return ErrInvalidAsset
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.pruneLocked(now)
	state, ok := m.states[reservation.nonce]
	if !ok || !state.expires.After(now) {
		return ErrReferenceExpired
	}
	if state.status != referenceReserved || !hmac.Equal([]byte(state.reservation), []byte(reservation.reservation)) {
		return ErrReferenceUsed
	}
	state.status = referenceUsed
	m.states[reservation.nonce] = state
	return nil
}

func (m *ReferenceManager) Release(reservation *ReferenceReservation) {
	if reservation == nil || reservation.nonce == "" || reservation.reservation == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[reservation.nonce]
	if !ok || state.status != referenceReserved || !hmac.Equal([]byte(state.reservation), []byte(reservation.reservation)) {
		return
	}
	state.status = referencePending
	state.reservation = ""
	m.states[reservation.nonce] = state
}

func (m *ReferenceManager) pruneLocked(now time.Time) {
	for m.expiry.Len() > 0 && !m.expiry[0].expires.After(now) {
		entry := heap.Pop(&m.expiry).(referenceExpiry)
		state, ok := m.states[entry.nonce]
		if !ok || !state.expires.Equal(entry.expires) {
			continue
		}
		delete(m.states, entry.nonce)
		m.owners[state.owner]--
		if m.owners[state.owner] <= 0 {
			delete(m.owners, state.owner)
		}
	}
}

func (m *ReferenceManager) removeState(nonce string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[nonce]
	if !ok {
		return
	}
	delete(m.states, nonce)
	m.owners[state.owner]--
	if m.owners[state.owner] <= 0 {
		delete(m.owners, state.owner)
	}
}
