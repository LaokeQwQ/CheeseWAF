package bot

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type ChallengeStatus string

const (
	ChallengePending ChallengeStatus = "pending"
	ChallengeUsed    ChallengeStatus = "used"
	ChallengeExpired ChallengeStatus = "expired"
)

var ErrChallengeCapacity = errors.New("challenge store capacity reached")

type ChallengeStoreConfig struct {
	Capacity           int
	PerOwnerCapacity   int
	PerPeerCapacity    int
	ConcurrentCapacity int
	PerOwnerConcurrent int
	PerPeerConcurrent  int
	UsedRetention      time.Duration
	RateWindow         time.Duration
	GlobalRate         int
	PerOwnerRate       int
	PerPeerRate        int
	Now                func() time.Time
}
type challengeEntry struct {
	status         ChallengeStatus
	expires, purge time.Time
	owner, peer    string
}
type ChallengeReservation struct {
	id, rateID  uint64
	owner, peer string
	expires     time.Time
}
type ChallengeStore struct {
	mu                          sync.Mutex
	m                           map[string]challengeEntry
	reservations                map[uint64]*ChallengeReservation
	ownerEntries, peerEntries   map[string]int
	ownerReserved, peerReserved map[string]int
	cap                         int
	perOwnerCap, perPeerCap     int
	concurrentCap               int
	perOwnerConcurrent          int
	perPeerConcurrent           int
	ret                         time.Duration
	rates                       *issuanceRateState
	now                         func() time.Time
	nextReservation             uint64
}

type ClearanceStateStore struct{ *ChallengeStore }

func NewClearanceStateStore(c ChallengeStoreConfig) *ClearanceStateStore {
	return &ClearanceStateStore{NewChallengeStore(c)}
}
func (s *ClearanceStateStore) Issue(jti, owner string, expires time.Time) error {
	return s.AddScoped(jti, owner, expires)
}
func (s *ClearanceStateStore) Valid(jti string) bool {
	return s != nil && s.Status(jti) == ChallengePending
}
func (s *ClearanceStateStore) Revoke(jti string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.now()
	s.clean(n, issuanceRateCleanupBudget)
	e, ok := s.m[jti]
	if !ok || !n.Before(e.expires) {
		return false
	}
	s.deleteEntryLocked(jti, e)
	return true
}

func NewChallengeStore(c ChallengeStoreConfig) *ChallengeStore {
	if c.Capacity < 1 {
		c.Capacity = 10000
	}
	if c.UsedRetention <= 0 {
		c.UsedRetention = 5 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.PerOwnerCapacity < 1 {
		c.PerOwnerCapacity = 8
	}
	if c.PerOwnerCapacity > c.Capacity {
		c.PerOwnerCapacity = c.Capacity
	}
	if c.PerPeerCapacity < 1 {
		c.PerPeerCapacity = min(c.Capacity, c.PerOwnerCapacity*4)
	}
	if c.PerPeerCapacity > c.Capacity {
		c.PerPeerCapacity = c.Capacity
	}
	if c.ConcurrentCapacity < 1 {
		c.ConcurrentCapacity = c.Capacity
		if c.RateWindow > 0 {
			c.ConcurrentCapacity = min(c.Capacity, 256)
		}
	}
	if c.ConcurrentCapacity > c.Capacity {
		c.ConcurrentCapacity = c.Capacity
	}
	if c.PerOwnerConcurrent < 1 {
		c.PerOwnerConcurrent = c.PerOwnerCapacity
		if c.RateWindow > 0 {
			c.PerOwnerConcurrent = min(c.PerOwnerCapacity, 2)
		}
	}
	if c.PerOwnerConcurrent > c.PerOwnerCapacity {
		c.PerOwnerConcurrent = c.PerOwnerCapacity
	}
	if c.PerPeerConcurrent < 1 {
		c.PerPeerConcurrent = c.PerPeerCapacity
		if c.RateWindow > 0 {
			c.PerPeerConcurrent = min(c.PerPeerCapacity, 16)
		}
	}
	if c.PerPeerConcurrent > c.PerPeerCapacity {
		c.PerPeerConcurrent = c.PerPeerCapacity
	}
	if c.RateWindow > 0 {
		if c.GlobalRate < 1 {
			c.GlobalRate = c.Capacity * 4
		}
		if c.PerOwnerRate < 1 {
			c.PerOwnerRate = c.PerOwnerCapacity * 4
		}
		if c.PerPeerRate < 1 {
			c.PerPeerRate = c.PerPeerCapacity * 4
		}
	}
	return &ChallengeStore{
		m:                  make(map[string]challengeEntry),
		reservations:       make(map[uint64]*ChallengeReservation),
		ownerEntries:       make(map[string]int),
		peerEntries:        make(map[string]int),
		ownerReserved:      make(map[string]int),
		peerReserved:       make(map[string]int),
		cap:                c.Capacity,
		perOwnerCap:        c.PerOwnerCapacity,
		perPeerCap:         c.PerPeerCapacity,
		concurrentCap:      c.ConcurrentCapacity,
		perOwnerConcurrent: c.PerOwnerConcurrent,
		perPeerConcurrent:  c.PerPeerConcurrent,
		ret:                c.UsedRetention,
		rates:              newIssuanceRateState(c.RateWindow, c.GlobalRate, c.PerOwnerRate, c.PerPeerRate),
		now:                c.Now,
	}
}
func (s *ChallengeStore) Add(j string, exp time.Time) error {
	return s.AddScoped(j, "", exp)
}
func (s *ChallengeStore) AddScoped(j, owner string, exp time.Time) error {
	return s.AddScopedWithPeer(j, owner, owner, exp)
}
func (s *ChallengeStore) AddScopedWithPeer(j, owner, peer string, exp time.Time) error {
	if j == "" || exp.IsZero() {
		return errors.New("jti and expiration required")
	}
	reservation, err := s.ReserveScoped(owner, peer, exp)
	if err != nil {
		return err
	}
	if err = s.Start(reservation); err != nil {
		s.Rollback(reservation)
		return err
	}
	if err = s.Commit(reservation, j, exp); err != nil {
		s.Rollback(reservation)
		return err
	}
	return nil
}
func (s *ChallengeStore) ReserveScoped(owner, peer string, exp time.Time) (*ChallengeReservation, error) {
	if s == nil || exp.IsZero() {
		return nil, errors.New("challenge store and expiration required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.now()
	s.clean(n, issuanceRateCleanupBudget)
	if !n.Before(exp) {
		return nil, errors.New("challenge already expired")
	}
	if len(s.m)+len(s.reservations) >= s.cap ||
		(owner != "" && s.ownerEntries[owner]+s.ownerReserved[owner] >= s.perOwnerCap) ||
		(peer != "" && s.peerEntries[peer]+s.peerReserved[peer] >= s.perPeerCap) ||
		len(s.reservations) >= s.concurrentCap ||
		(owner != "" && s.ownerReserved[owner] >= s.perOwnerConcurrent) ||
		(peer != "" && s.peerReserved[peer] >= s.perPeerConcurrent) {
		return nil, ErrChallengeCapacity
	}
	rateOwner, ratePeer := owner, peer
	if rateOwner == "" {
		rateOwner = "unscoped"
	}
	if ratePeer == "" {
		ratePeer = rateOwner
	}
	rateID, err := s.rates.reserve(n, rateOwner, ratePeer)
	if err != nil {
		return nil, err
	}
	s.nextReservation++
	if s.nextReservation == 0 {
		s.nextReservation++
	}
	reservation := &ChallengeReservation{id: s.nextReservation, rateID: rateID, owner: owner, peer: peer, expires: generationReservationExpiry(n, exp)}
	s.reservations[reservation.id] = reservation
	if owner != "" {
		s.ownerReserved[owner]++
	}
	if peer != "" {
		s.peerReserved[peer]++
	}
	return reservation, nil
}
func (s *ChallengeStore) Start(reservation *ChallengeReservation) error {
	if s == nil || reservation == nil {
		return errors.New("challenge reservation required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.reservations[reservation.id]
	if !ok || stored != reservation || !s.now().Before(reservation.expires) {
		return errors.New("challenge reservation is stale")
	}
	if !s.rates.start(reservation.rateID) {
		return errors.New("challenge rate reservation is stale")
	}
	return nil
}
func (s *ChallengeStore) Commit(reservation *ChallengeReservation, j string, exp time.Time) error {
	if s == nil || reservation == nil || j == "" || exp.IsZero() {
		return errors.New("challenge reservation, jti, and expiration required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.reservations[reservation.id]
	if !ok || stored != reservation {
		return errors.New("challenge reservation is stale")
	}
	n := s.now()
	if !n.Before(reservation.expires) || !n.Before(exp) {
		s.rollbackReservationLocked(reservation)
		return errors.New("challenge reservation expired")
	}
	if _, exists := s.m[j]; exists {
		s.rollbackReservationLocked(reservation)
		return errors.New("duplicate jti")
	}
	if !s.rates.started(reservation.rateID) {
		s.rollbackReservationLocked(reservation)
		return errors.New("challenge work was not started")
	}
	s.removeReservationLocked(reservation)
	s.m[j] = challengeEntry{status: ChallengePending, expires: exp, purge: exp, owner: reservation.owner, peer: reservation.peer}
	if reservation.owner != "" {
		s.ownerEntries[reservation.owner]++
	}
	if reservation.peer != "" {
		s.peerEntries[reservation.peer]++
	}
	return nil
}
func (s *ChallengeStore) Rollback(reservation *ChallengeReservation) bool {
	if s == nil || reservation == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rollbackReservationLocked(reservation)
}
func (s *ChallengeStore) Consume(j string) (ChallengeStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.now()
	s.clean(n, issuanceRateCleanupBudget)
	e, ok := s.m[j]
	if !ok {
		return ChallengeExpired, false
	}
	if !n.Before(e.expires) {
		s.deleteEntryLocked(j, e)
		return ChallengeExpired, false
	}
	if e.status != ChallengePending {
		return e.status, false
	}
	s.deleteEntryLocked(j, e)
	return ChallengeUsed, true
}
func (s *ChallengeStore) Status(j string) ChallengeStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.now()
	s.clean(n, issuanceRateCleanupBudget)
	e, ok := s.m[j]
	if !ok || !n.Before(e.expires) {
		if ok {
			s.deleteEntryLocked(j, e)
		}
		return ChallengeExpired
	}
	return e.status
}
func (s *ChallengeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for j, entry := range s.m {
		if !now.Before(entry.purge) {
			s.deleteEntryLocked(j, entry)
		}
	}
	for _, reservation := range s.reservations {
		if !now.Before(reservation.expires) {
			s.rollbackReservationLocked(reservation)
		}
	}
	if s.rates != nil {
		for s.rates.clean(now, issuanceRateCleanupBudget) == issuanceRateCleanupBudget {
		}
	}
	return len(s.m)
}
func (s *ChallengeStore) Remove(j string) bool {
	if s == nil || j == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[j]
	if !ok {
		return false
	}
	s.deleteEntryLocked(j, e)
	return true
}
func (s *ChallengeStore) clean(n time.Time, budget int) int {
	cleaned, inspected := 0, 0
	for j, e := range s.m {
		if inspected >= budget {
			break
		}
		inspected++
		if !n.Before(e.purge) {
			s.deleteEntryLocked(j, e)
			cleaned++
		}
	}
	for _, reservation := range s.reservations {
		if inspected >= budget {
			break
		}
		inspected++
		if !n.Before(reservation.expires) {
			s.rollbackReservationLocked(reservation)
			cleaned++
		}
	}
	if s.rates != nil && inspected < budget {
		cleaned += s.rates.clean(n, budget-inspected)
	}
	return cleaned
}
func (s *ChallengeStore) rollbackReservationLocked(reservation *ChallengeReservation) bool {
	if reservation == nil || s.reservations[reservation.id] != reservation {
		return false
	}
	s.rates.rollback(reservation.rateID)
	s.removeReservationLocked(reservation)
	return true
}
func (s *ChallengeStore) removeReservationLocked(reservation *ChallengeReservation) {
	delete(s.reservations, reservation.id)
	if reservation.owner != "" {
		decrementIssueCount(s.ownerReserved, reservation.owner)
	}
	if reservation.peer != "" {
		decrementIssueCount(s.peerReserved, reservation.peer)
	}
}
func (s *ChallengeStore) deleteEntryLocked(j string, entry challengeEntry) {
	delete(s.m, j)
	if entry.owner != "" {
		decrementIssueCount(s.ownerEntries, entry.owner)
	}
	if entry.peer != "" {
		decrementIssueCount(s.peerEntries, entry.peer)
	}
}

type FailureKey struct{ Client, Site, Policy string }
type FailureTrackerConfig struct {
	Capacity        int
	Window, IdleTTL time.Duration
	LevelAt         []int
	BlockAt         int
	BlockDuration   time.Duration
	Now             func() time.Time
}
type FailureDecision struct {
	Failures, Level int
	Blocked         bool
	BlockedUntil    time.Time
}
type failureEntry struct {
	at            []time.Time
	blocked, last time.Time
}
type FailureTracker struct {
	mu               sync.Mutex
	m                map[FailureKey]*failureEntry
	cap              int
	win, idle, block time.Duration
	levels           []int
	blockAt          int
	now              func() time.Time
}

func NewFailureTracker(c FailureTrackerConfig) (*FailureTracker, error) {
	if c.Window <= 0 || c.BlockDuration <= 0 {
		return nil, errors.New("positive window and block duration required")
	}
	if c.Capacity < 1 {
		c.Capacity = 10000
	}
	if c.IdleTTL <= 0 {
		c.IdleTTL = c.Window + c.BlockDuration
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	sort.Ints(c.LevelAt)
	return &FailureTracker{m: map[FailureKey]*failureEntry{}, cap: c.Capacity, win: c.Window, idle: c.IdleTTL, block: c.BlockDuration, levels: append([]int(nil), c.LevelAt...), blockAt: c.BlockAt, now: c.Now}, nil
}
func (t *FailureTracker) RecordFailure(k FailureKey) (FailureDecision, error) {
	if strings.TrimSpace(k.Client) == "" || k.Site == "" || k.Policy == "" {
		return FailureDecision{}, errors.New("complete key required")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.now()
	t.clean(n)
	e := t.m[k]
	if e == nil {
		if len(t.m) >= t.cap {
			return FailureDecision{}, errors.New("failure tracker capacity reached")
		}
		e = &failureEntry{}
		t.m[k] = e
	}
	t.trim(e, n)
	e.at = append(e.at, n)
	e.last = n
	if t.blockAt > 0 && len(e.at) >= t.blockAt {
		e.blocked = n.Add(t.block)
	}
	return t.result(e, n), nil
}
func (t *FailureTracker) Check(k FailureKey) FailureDecision {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.now()
	t.clean(n)
	e := t.m[k]
	if e == nil {
		return FailureDecision{}
	}
	t.trim(e, n)
	return t.result(e, n)
}
func (t *FailureTracker) Reset(k FailureKey) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.m, k)
	t.mu.Unlock()
}

func (t *FailureTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clean(t.now())
	return len(t.m)
}
func (t *FailureTracker) result(e *failureEntry, n time.Time) FailureDecision {
	l := 0
	for _, x := range t.levels {
		if x > 0 && len(e.at) >= x {
			l++
		}
	}
	return FailureDecision{len(e.at), l, n.Before(e.blocked), e.blocked}
}
func (t *FailureTracker) trim(e *failureEntry, n time.Time) {
	cut := n.Add(-t.win)
	i := 0
	for i < len(e.at) && e.at[i].Before(cut) {
		i++
	}
	e.at = append(e.at[:0], e.at[i:]...)
	if !n.Before(e.blocked) {
		e.blocked = time.Time{}
	}
}
func (t *FailureTracker) clean(n time.Time) {
	for k, e := range t.m {
		t.trim(e, n)
		if len(e.at) == 0 && !n.Before(e.last.Add(t.idle)) {
			delete(t.m, k)
		}
	}
}

const ClearanceClaimsVersion = 1

type BindingMode string

const (
	BindingStrictIPUA BindingMode = "strict_ip_ua"
	BindingIPPrefixUA BindingMode = "ip_prefix_ua"
)

type ClearanceClaims struct {
	Version       int    `json:"v"`
	JTI           string `json:"jti"`
	Site          string `json:"site"`
	Policy        string `json:"policy"`
	PolicyVersion string `json:"policy_version"`
	Level         int    `json:"level"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	RequestMethod string `json:"request_method,omitempty"`
	Binding       string `json:"binding"`
	IssuedAt      int64  `json:"iat"`
	ExpiresAt     int64  `json:"exp"`
	KeyID         string `json:"key_id"`
}
type ClearanceContext struct {
	Site, Policy, PolicyVersion, ClientIP, UserAgent string
	Path, RequestMethod                              string
	BindingMode                                      BindingMode
}
type ClearanceSignerConfig struct {
	Keys              map[string][]byte
	ActiveKeyID       string
	MaxTTL, ClockSkew time.Duration
	Now               func() time.Time
}
type ClearanceSigner struct {
	keys      map[string][]byte
	active    string
	ttl, skew time.Duration
	now       func() time.Time
}

func NewClearanceSigner(c ClearanceSignerConfig) (*ClearanceSigner, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.MaxTTL <= 0 {
		c.MaxTTL = 24 * time.Hour
	}
	ks := map[string][]byte{}
	for id, k := range c.Keys {
		if id == "" || len(k) < 32 {
			return nil, errors.New("keys need id and 32 bytes")
		}
		ks[id] = append([]byte(nil), k...)
	}
	if _, ok := ks[c.ActiveKeyID]; !ok {
		return nil, errors.New("active key missing")
	}
	return &ClearanceSigner{ks, c.ActiveKeyID, c.MaxTTL, c.ClockSkew, c.Now}, nil
}
func ComputeClearanceBinding(m BindingMode, addr, ua string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return "", errors.New("invalid ip")
	}
	var scope string
	switch m {
	case BindingStrictIPUA:
		scope = ip.String()
	case BindingIPPrefixUA:
		if v := ip.To4(); v != nil {
			v[3] = 0
			scope = v.String() + "/24"
		} else {
			scope = ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
		}
	default:
		return "", errors.New("unsupported binding")
	}
	x := sha256.Sum256([]byte(string(m) + "\x00" + scope + "\x00" + strings.TrimSpace(ua)))
	return base64.RawURLEncoding.EncodeToString(x[:]), nil
}
func (s *ClearanceSigner) Sign(c ClearanceClaims) (string, error) {
	c.Version = 1
	c.KeyID = s.active
	if c.IssuedAt == 0 {
		c.IssuedAt = s.now().Unix()
	}
	if e := s.valid(c, s.now()); e != nil {
		return "", e
	}
	b, _ := json.Marshal(c)
	p := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.keys[c.KeyID])
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}
func (s *ClearanceSigner) Verify(tok string, x ClearanceContext) (ClearanceClaims, error) {
	c, e := s.Authenticate(tok)
	if e != nil {
		return ClearanceClaims{}, e
	}
	if c.Site != x.Site || c.Policy != x.Policy || c.PolicyVersion != x.PolicyVersion {
		return c, errors.New("scope mismatch")
	}
	if !pathWithinScope(x.Path, c.Path) || (c.RequestMethod != "" && !strings.EqualFold(c.RequestMethod, x.RequestMethod)) {
		return c, errors.New("request scope mismatch")
	}
	want, e := ComputeClearanceBinding(x.BindingMode, x.ClientIP, x.UserAgent)
	if e != nil || !hmac.Equal([]byte(c.Binding), []byte(want)) {
		return c, errors.New("binding mismatch")
	}
	return c, nil
}
func (s *ClearanceSigner) Authenticate(tok string) (ClearanceClaims, error) {
	var c ClearanceClaims
	if len(tok) == 0 || len(tok) > maxClearanceTokenBytes {
		return c, errors.New("token too large")
	}
	p := strings.Split(tok, ".")
	if len(p) != 2 {
		return c, errors.New("malformed token")
	}
	b, e := base64.RawURLEncoding.DecodeString(p[0])
	if e != nil || json.Unmarshal(b, &c) != nil {
		return c, errors.New("invalid claims")
	}
	k, ok := s.keys[c.KeyID]
	if !ok {
		return c, errors.New("unknown key")
	}
	sig, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return c, e
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(p[0]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return c, errors.New("invalid signature")
	}
	if e = s.valid(c, s.now()); e != nil {
		return c, e
	}
	return c, nil
}
func (s *ClearanceSigner) valid(c ClearanceClaims, n time.Time) error {
	if c.Version != 1 || c.JTI == "" || c.Site == "" || c.Policy == "" || c.PolicyVersion == "" || c.Method == "" || c.Path == "" || c.Binding == "" || c.KeyID == "" {
		return errors.New("incomplete claims")
	}
	iat, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.ExpiresAt, 0)
	if c.ExpiresAt <= c.IssuedAt || exp.Sub(iat) > s.ttl {
		return errors.New("invalid lifetime")
	}
	if n.Add(s.skew).Before(iat) {
		return errors.New("future token")
	}
	if !n.Add(-s.skew).Before(exp) {
		return errors.New("expired token")
	}
	return nil
}

func pathWithinScope(path, scope string) bool {
	cleanedPath, ok := engine.NormalizeRequestPath(path)
	if !ok {
		return false
	}
	cleanedScope, ok := engine.NormalizeRequestPath(scope)
	if !ok {
		return false
	}
	if cleanedScope == "/" {
		return true
	}
	return engine.PathMatchesPrefix(cleanedPath, cleanedScope)
}

const PoWProtocolVersion = 2
const powTokenPrefix = "p3."

var ErrPoWInvalid = errors.New("invalid proof")

const (
	maxClearanceTokenBytes = 8192
	maxPoWTokenBytes       = 4096
	maxPoWAnswerBytes      = 128
)

type PoWChallenge struct {
	Token string
	Work  int
	jti   string
}
type PoWContext struct {
	Site, Policy, PolicyVersion, Path, ClientKey, PeerKey string
	Risk                                                  int
}
type PoWManager struct {
	secret     []byte
	aead       cipher.AEAD
	store      *ChallengeStore
	now        func() time.Time
	ttl        time.Duration
	base, max  int
	algorithms map[string]struct{}
}

func NewPoWManager(secret []byte, store *ChallengeStore, ttl time.Duration, base, max int, algorithms []string, now func() time.Time) (*PoWManager, error) {
	if len(secret) < 16 || store == nil {
		return nil, errors.New("pow secret and store required")
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if base < 1 {
		base = 4
	}
	if max < base {
		max = base
	}
	if max > 8 {
		max = 8
	}
	if now == nil {
		now = time.Now
	}
	a := map[string]struct{}{}
	for _, v := range algorithms {
		if strings.EqualFold(v, "sha256") {
			a["sha256"] = struct{}{}
		}
	}
	if len(a) == 0 {
		a["sha256"] = struct{}{}
	}
	key := sha256.Sum256(append(append([]byte(nil), secret...), []byte("pow-aead-v3")...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &PoWManager{secret: append([]byte(nil), secret...), aead: aead, store: store, now: now, ttl: ttl, base: base, max: max, algorithms: a}, nil
}
func (m *PoWManager) Issue(x PoWContext) (PoWChallenge, error) {
	return m.issueWithSuite(x, "sha256")
}
func (m *PoWManager) issueWithSuite(x PoWContext, suite string) (PoWChallenge, error) {
	now := m.now()
	expires := now.Add(m.ttl)
	owner := x.Site + "\x00" + x.ClientKey
	peer := strings.TrimSpace(x.PeerKey)
	if peer == "" {
		client := x.ClientKey
		if index := strings.IndexByte(client, '\n'); index >= 0 {
			client = client[:index]
		}
		peer = x.Site + "\x00" + client
	}
	reservation, err := m.store.ReserveScoped(owner, peer, expires)
	if err != nil {
		return PoWChallenge{}, err
	}
	committed := false
	defer func() {
		if !committed {
			m.store.Rollback(reservation)
		}
	}()
	if err = m.store.Start(reservation); err != nil {
		return PoWChallenge{}, err
	}
	b := make([]byte, 18)
	if _, e := rand.Read(b); e != nil {
		return PoWChallenge{}, e
	}
	j := base64.RawURLEncoding.EncodeToString(b)
	exp := expires.Unix()
	work := m.base + x.Risk
	if work > m.max {
		work = m.max
	}
	claims := struct {
		Version                                                  int
		JTI, Site, Policy, PolicyVersion, Path, ClientKey, Suite string
		Work                                                     int
		Expires                                                  int64
	}{PoWProtocolVersion, j, x.Site, x.Policy, x.PolicyVersion, x.Path, x.ClientKey, suite, work, exp}
	plain, err := json.Marshal(claims)
	if err != nil {
		return PoWChallenge{}, err
	}
	nonce := make([]byte, m.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return PoWChallenge{}, err
	}
	tok := powTokenPrefix + base64.RawURLEncoding.EncodeToString(m.aead.Seal(nonce, nonce, plain, []byte(powTokenPrefix)))
	if e := m.store.Commit(reservation, j, time.Unix(exp, 0)); e != nil {
		return PoWChallenge{}, e
	}
	committed = true
	return PoWChallenge{Token: tok, Work: work, jti: j}, nil
}
func (m *PoWManager) Revoke(challenge PoWChallenge) bool {
	return m != nil && m.store != nil && challenge.jti != "" && m.store.Remove(challenge.jti)
}
func (m *PoWManager) Verify(token, answer string, x PoWContext) error {
	if len(token) == 0 || len(token) > maxPoWTokenBytes || len(answer) == 0 || len(answer) > maxPoWAnswerBytes {
		return ErrPoWInvalid
	}
	if !strings.HasPrefix(token, powTokenPrefix) {
		return ErrPoWInvalid
	}
	raw, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, powTokenPrefix))
	if e != nil {
		return ErrPoWInvalid
	}
	if len(raw) < m.aead.NonceSize() {
		return ErrPoWInvalid
	}
	plain, e := m.aead.Open(nil, raw[:m.aead.NonceSize()], raw[m.aead.NonceSize():], []byte(powTokenPrefix))
	if e != nil {
		return ErrPoWInvalid
	}
	var c struct {
		Version                                                  int
		JTI, Site, Policy, PolicyVersion, Path, ClientKey, Suite string
		Work                                                     int
		Expires                                                  int64
	}
	if json.Unmarshal(plain, &c) != nil || c.Version != PoWProtocolVersion || c.Site != x.Site || c.Policy != x.Policy || c.PolicyVersion != x.PolicyVersion || c.Path != x.Path || c.ClientKey != x.ClientKey {
		return ErrPoWInvalid
	}
	if _, ok := m.algorithms[c.Suite]; !ok {
		return ErrPoWInvalid
	}
	if c.Work < 1 || c.Work > m.max || c.Expires <= m.now().Unix() {
		return ErrPoWInvalid
	}
	sum := sha256.Sum256([]byte(token + "\x00" + answer))
	if !hasLeadingZeroNibbles(sum[:], c.Work) {
		return ErrPoWInvalid
	}
	if st, ok := m.store.Consume(c.JTI); !ok || st != ChallengeUsed {
		return ErrPoWInvalid
	}
	return nil
}
func hasLeadingZeroNibbles(sum []byte, n int) bool {
	for i := 0; i < n; i++ {
		b := sum[i/2]
		if i%2 == 0 {
			if b>>4 != 0 {
				return false
			}
		} else if b&15 != 0 {
			return false
		}
	}
	return true
}
