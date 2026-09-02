package deploy

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrAuthorizationInvalid = errors.New("ssh precheck authorization is invalid, expired, or already used")

type AuthorizationTarget struct {
	Host          string
	User          string
	Port          int
	HostKeySHA256 string
	Action        string
	TaskID        string
	BinarySHA256  string
	ResolvedIPs   []string
}
type Authorization struct {
	Handle    string    `json:"handle"`
	ExpiresAt time.Time `json:"expires_at"`
}
type authorizationRecord struct {
	target    AuthorizationTarget
	expiresAt time.Time
}
type AuthorizationStoreOptions struct {
	TTL      time.Duration
	Now      func() time.Time
	NewToken func() (string, error)
}
type AuthorizationStore struct {
	mu       sync.Mutex
	ttl      time.Duration
	now      func() time.Time
	newToken func() (string, error)
	records  map[string]authorizationRecord
	byTask   map[string]string
}

func NewAuthorizationStore(o AuthorizationStoreOptions) *AuthorizationStore {
	if o.TTL <= 0 {
		o.TTL = 5 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.NewToken == nil {
		o.NewToken = randomAuthorizationToken
	}
	return &AuthorizationStore{ttl: o.TTL, now: o.Now, newToken: o.NewToken, records: map[string]authorizationRecord{}, byTask: map[string]string{}}
}
func (s *AuthorizationStore) Issue(task string, t AuthorizationTarget) (Authorization, error) {
	return s.issue(task, t, false)
}

// IssueBound creates an authorization suitable for network execution. The
// resolved numeric set is mandatory so a later consumer never needs to resolve
// the hostname again.
func (s *AuthorizationStore) IssueBound(task string, t AuthorizationTarget) (Authorization, error) {
	return s.issue(task, t, true)
}

func (s *AuthorizationStore) issue(task string, t AuthorizationTarget, requireBinding bool) (Authorization, error) {
	now := s.now().UTC()
	t = NormalizeAuthorizationTarget(t)
	if requireBinding {
		if err := validateAuthorizationBinding(t.ResolvedIPs); err != nil {
			return Authorization{}, err
		}
	}
	task = strings.TrimSpace(task)
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.byTask[task]; h != "" {
		if r, ok := s.records[h]; ok && authorizationTargetsEqual(r.target, t) && now.Before(r.expiresAt) {
			return Authorization{h, r.expiresAt}, nil
		}
	}
	h, e := s.newToken()
	if e != nil {
		return Authorization{}, e
	}
	x := now.Add(s.ttl)
	s.records[h] = authorizationRecord{cloneAuthorizationTarget(t), x}
	if task != "" {
		s.byTask[task] = h
	}
	return Authorization{h, x}, nil
}

func (s *AuthorizationStore) GetByTask(task string) (Authorization, bool) {
	if s == nil || strings.TrimSpace(task) == "" {
		return Authorization{}, false
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	handle := s.byTask[strings.TrimSpace(task)]
	record, ok := s.records[handle]
	if !ok || !now.Before(record.expiresAt) {
		return Authorization{}, false
	}
	return Authorization{Handle: handle, ExpiresAt: record.expiresAt}, true
}
func (s *AuthorizationStore) Consume(h string, t AuthorizationTarget) error {
	_, err := s.consume(h, t, false)
	return err
}

// ConsumeBound atomically consumes a single-use authorization and returns the
// numeric addresses captured by the successful precheck.
func (s *AuthorizationStore) ConsumeBound(h string, t AuthorizationTarget) (AuthorizationTarget, error) {
	return s.consume(h, t, true)
}

func (s *AuthorizationStore) consume(h string, t AuthorizationTarget, requireBinding bool) (AuthorizationTarget, error) {
	if s == nil {
		return AuthorizationTarget{}, ErrAuthorizationInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	handle := strings.TrimSpace(h)
	r, ok := s.records[handle]
	if !ok || !s.now().UTC().Before(r.expiresAt) || !authorizationTargetsMatch(r.target, NormalizeAuthorizationTarget(t)) {
		return AuthorizationTarget{}, ErrAuthorizationInvalid
	}
	if requireBinding {
		if err := validateAuthorizationBinding(r.target.ResolvedIPs); err != nil {
			return AuthorizationTarget{}, ErrAuthorizationInvalid
		}
	}
	delete(s.records, handle)
	for k, v := range s.byTask {
		if v == handle {
			delete(s.byTask, k)
		}
	}
	return cloneAuthorizationTarget(r.target), nil
}
func NormalizeAuthorizationTarget(t AuthorizationTarget) AuthorizationTarget {
	t.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(t.Host)), ".")
	t.User = strings.TrimSpace(t.User)
	if t.Port <= 0 {
		t.Port = 22
	}
	t.HostKeySHA256 = strings.TrimSpace(t.HostKeySHA256)
	if len(t.HostKeySHA256) >= 7 && strings.EqualFold(t.HostKeySHA256[:7], "SHA256:") {
		t.HostKeySHA256 = "SHA256:" + t.HostKeySHA256[7:]
	}
	t.Action = strings.ToLower(strings.TrimSpace(t.Action))
	t.TaskID = strings.TrimSpace(t.TaskID)
	t.BinarySHA256 = strings.ToLower(strings.TrimSpace(t.BinarySHA256))
	t.ResolvedIPs = normalizeAuthorizationBinding(t.ResolvedIPs)
	return t
}

func normalizeAuthorizationBinding(addresses []string) []string {
	unique := make(map[string]struct{}, len(addresses))
	for _, value := range addresses {
		value = strings.TrimSpace(value)
		if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
			value = address.Unmap().String()
		}
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for value := range unique {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		left, leftErr := netip.ParseAddr(out[i])
		right, rightErr := netip.ParseAddr(out[j])
		if leftErr == nil && rightErr == nil {
			return left.Compare(right) < 0
		}
		return out[i] < out[j]
	})
	return out
}

func validateAuthorizationBinding(addresses []string) error {
	if len(addresses) == 0 {
		return fmt.Errorf("ssh precheck authorization requires resolved numeric addresses")
	}
	for _, value := range addresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return fmt.Errorf("ssh precheck authorization contains an invalid numeric address")
		}
	}
	return nil
}

func cloneAuthorizationTarget(t AuthorizationTarget) AuthorizationTarget {
	t.ResolvedIPs = append([]string(nil), t.ResolvedIPs...)
	return t
}

func authorizationTargetsEqual(left, right AuthorizationTarget) bool {
	if !authorizationTargetsMatch(left, right) || left.Action != right.Action || left.TaskID != right.TaskID || left.BinarySHA256 != right.BinarySHA256 {
		return false
	}
	if len(left.ResolvedIPs) != len(right.ResolvedIPs) {
		return false
	}
	for i := range left.ResolvedIPs {
		if left.ResolvedIPs[i] != right.ResolvedIPs[i] {
			return false
		}
	}
	return true
}

// authorizationTargetsMatch enforces the full request fingerprint. Host, User,
// Port and HostKeySHA256 must always match exactly. Action, TaskID and
// BinarySHA256 are bound only when the issued record carries a non-empty value;
// an empty value means the issuer did not bind that dimension (e.g. a generic
// connectivity check), so the consumer is not constrained for it.
func authorizationTargetsMatch(issued, consumed AuthorizationTarget) bool {
	if issued.Host != consumed.Host || issued.User != consumed.User || issued.Port != consumed.Port || issued.HostKeySHA256 != consumed.HostKeySHA256 {
		return false
	}
	if issued.Action != "" && issued.Action != consumed.Action {
		return false
	}
	if issued.TaskID != "" && issued.TaskID != consumed.TaskID {
		return false
	}
	if issued.BinarySHA256 != "" && issued.BinarySHA256 != consumed.BinarySHA256 {
		return false
	}
	return true
}
func randomAuthorizationToken() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), e
}
