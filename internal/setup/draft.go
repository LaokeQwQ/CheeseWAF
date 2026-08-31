package setup

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const (
	// SetupSessionCookie is the server-side draft binder (HttpOnly).
	SetupSessionCookie = "cheesewaf_setup_session"
	// DefaultDraftTTL discards incomplete drafts.
	DefaultDraftTTL  = 30 * time.Minute
	DefaultMaxDrafts = 100
)

var (
	// ErrDraftStoreFull is returned when max draft capacity is reached.
	ErrDraftStoreFull = errors.New("draft store full")
	// ErrDraftProbeInProgress prevents duplicate probe I/O for one session.
	ErrDraftProbeInProgress = errors.New("draft probe already in progress")
)

// IntegrationsConfig captures optional external integrations entered during setup.
// Values are stored in the draft but are not applied to the live config until the
// operator saves them under System Settings after installation.
type IntegrationsConfig struct {
	PostgresEnabled   bool   `json:"postgresEnabled"`
	PostgresDSN       string `json:"postgresDsn"`
	PostgresTable     string `json:"postgresTable"`
	PrometheusEnabled bool   `json:"prometheusEnabled"`
	PrometheusPath    string `json:"prometheusPath"`
	PrometheusPublic  bool   `json:"prometheusPublic"`
	VictoriaEnabled   bool   `json:"victoriaEnabled"`
	VictoriaEndpoint  string `json:"victoriaEndpoint"`
}

// SetupDraft holds multi-step wizard state until final confirmation.
type SetupDraft struct {
	ID            string             `json:"id"`
	CreatedAt     time.Time          `json:"created_at"`
	ExpiresAt     time.Time          `json:"expires_at"`
	Probe         *ProbeResult       `json:"probe,omitempty"`
	Profile       HardwareProfile    `json:"profile,omitempty"`
	Custom        *ProfileConfig     `json:"custom,omitempty"`
	Username      string             `json:"username,omitempty"`
	AdminListen   string             `json:"admin_listen,omitempty"`
	AdminStrategy string             `json:"admin_strategy,omitempty"`
	Integrations  *IntegrationsConfig `json:"integrations,omitempty"`
	PasswordSet   bool               `json:"password_set"`
	Confirmed     bool               `json:"confirmed"`
	password      string             // never JSON-serialized
	probeRunning  bool
}

// DraftStore is an in-memory draft registry keyed by setup session id.
type DraftStore struct {
	mu        sync.Mutex
	items     map[string]*SetupDraft
	ttl       time.Duration
	maxDrafts int
	now       func() time.Time
}

// NewDraftStore creates a draft store with the given TTL.
func NewDraftStore(ttl time.Duration) *DraftStore {
	return NewDraftStoreWithLimit(ttl, DefaultMaxDrafts)
}

// NewDraftStoreWithLimit creates a draft store with an explicit capacity.
func NewDraftStoreWithLimit(ttl time.Duration, maxDrafts int) *DraftStore {
	if ttl <= 0 {
		ttl = DefaultDraftTTL
	}
	if maxDrafts <= 0 {
		maxDrafts = DefaultMaxDrafts
	}
	return &DraftStore{items: map[string]*SetupDraft{}, ttl: ttl, maxDrafts: maxDrafts, now: time.Now}
}

// Create allocates a new draft and returns it.
func (s *DraftStore) Create() (*SetupDraft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	// Enforce max drafts to prevent memory exhaustion from repeated probe calls
	if len(s.items) >= s.maxDrafts {
		return nil, ErrDraftStoreFull
	}
	id, err := randomDraftID()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	d := &SetupDraft{
		ID:        id,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.items[id] = d
	return cloneDraft(d), nil
}

// ReserveProbe atomically reuses a completed probe, reserves an existing
// draft, or creates and reserves a new draft.
func (s *DraftStore) ReserveProbe(id string) (*SetupDraft, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	if d := s.items[id]; d != nil {
		if d.Probe != nil {
			return cloneDraft(d), true, nil
		}
		if d.probeRunning {
			return nil, false, ErrDraftProbeInProgress
		}
		d.probeRunning = true
		return cloneDraft(d), false, nil
	}
	if len(s.items) >= s.maxDrafts {
		return nil, false, ErrDraftStoreFull
	}
	newID, err := randomDraftID()
	if err != nil {
		return nil, false, err
	}
	now := s.now().UTC()
	d := &SetupDraft{ID: newID, CreatedAt: now, ExpiresAt: now.Add(s.ttl), probeRunning: true}
	s.items[newID] = d
	return cloneDraft(d), false, nil
}

// CompleteProbe stores a reserved probe result.
func (s *DraftStore) CompleteProbe(id string, result ProbeResult) (*SetupDraft, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	d := s.items[id]
	if d == nil || !d.probeRunning {
		return nil, false
	}
	d.Probe = &result
	d.Profile = result.Profile
	d.probeRunning = false
	return cloneDraft(d), true
}

// Get returns a draft by id if present and not expired.
func (s *DraftStore) Get(id string) (*SetupDraft, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	d, ok := s.items[id]
	if !ok {
		return nil, false
	}
	return cloneDraft(d), true
}

// Update merges non-zero fields into the draft.
func (s *DraftStore) Update(id string, mut func(*SetupDraft)) (*SetupDraft, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	d, ok := s.items[id]
	if !ok {
		return nil, false
	}
	if mut != nil {
		mut(d)
	}
	return cloneDraft(d), true
}

// SetPassword stores the admin password in the draft (memory only).
func (s *DraftStore) SetPassword(id, password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	d, ok := s.items[id]
	if !ok {
		return false
	}
	d.password = password
	d.PasswordSet = password != ""
	return true
}

// Password returns the stored password for CompleteSetup.
func (s *DraftStore) Password(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	d, ok := s.items[id]
	if !ok {
		return "", false
	}
	return d.password, d.PasswordSet
}

// Delete removes a draft.
func (s *DraftStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, id)
}

func (s *DraftStore) purgeLocked() {
	now := s.now().UTC()
	for id, d := range s.items {
		if !now.Before(d.ExpiresAt) {
			delete(s.items, id)
		}
	}
}

func cloneDraft(d *SetupDraft) *SetupDraft {
	if d == nil {
		return nil
	}
	// JSON round-trip drops password.
	raw, _ := json.Marshal(d)
	var out SetupDraft
	_ = json.Unmarshal(raw, &out)
	return &out
}

func randomDraftID() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
