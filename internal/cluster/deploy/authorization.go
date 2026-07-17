package deploy

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	now := s.now().UTC()
	t = NormalizeAuthorizationTarget(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if h := s.byTask[task]; h != "" {
		if r, ok := s.records[h]; ok && r.target == t && now.Before(r.expiresAt) {
			return Authorization{h, r.expiresAt}, nil
		}
	}
	h, e := s.newToken()
	if e != nil {
		return Authorization{}, e
	}
	x := now.Add(s.ttl)
	s.records[h] = authorizationRecord{t, x}
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
	if s == nil {
		return ErrAuthorizationInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[strings.TrimSpace(h)]
	if !ok || !s.now().UTC().Before(r.expiresAt) || r.target != NormalizeAuthorizationTarget(t) {
		return ErrAuthorizationInvalid
	}
	delete(s.records, h)
	for k, v := range s.byTask {
		if v == h {
			delete(s.byTask, k)
		}
	}
	return nil
}
func NormalizeAuthorizationTarget(t AuthorizationTarget) AuthorizationTarget {
	t.Host = strings.ToLower(strings.TrimSpace(t.Host))
	t.User = strings.TrimSpace(t.User)
	if t.Port <= 0 {
		t.Port = 22
	}
	t.HostKeySHA256 = strings.TrimSpace(t.HostKeySHA256)
	if len(t.HostKeySHA256) >= 7 && strings.EqualFold(t.HostKeySHA256[:7], "SHA256:") {
		t.HostKeySHA256 = "SHA256:" + t.HostKeySHA256[7:]
	}
	return t
}
func randomAuthorizationToken() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:]), e
}
