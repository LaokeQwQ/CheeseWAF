// Package netlease defines the no-I/O contract for offline egress policy and
// short-lived, administrator-approved plugin socket leases.
package netlease

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const MaxLeaseTTL = 10 * time.Minute

var (
	ErrExternalEgressDenied  = errors.New("external egress denied")
	ErrResourceNotAllowed    = errors.New("resource is not allowed")
	ErrPolicyEpoch           = errors.New("network policy epoch mismatch")
	ErrLeaseExpired          = errors.New("socket lease expired")
	ErrLeaseRevoked          = errors.New("socket lease revoked")
	ErrLeaseScope            = errors.New("socket lease scope mismatch")
	ErrLeaseConsumed         = errors.New("socket lease already consumed")
	ErrLeaseNotConsumed      = errors.New("socket lease has not been consumed")
	ErrInvalidLease          = errors.New("invalid socket lease")
	ErrLeaseTTL              = errors.New("socket lease TTL exceeds platform limit")
	ErrConfirmationRequired  = errors.New("administrator confirmation is required")
	ErrConfirmationExpired   = errors.New("administrator confirmation expired")
	ErrUsageLimit            = errors.New("socket lease usage limit exceeded")
	ErrConfirmationReplay    = errors.New("administrator confirmation already used")
	ErrTemporaryEgressDenied = errors.New("temporary egress is not enabled")
)

type Target struct {
	Host     string
	Port     int
	Protocol string
}
type Resource = Target

// Validate checks a target without resolving DNS or opening a socket.
// Network-facing callers must reject ambiguous host/protocol strings instead
// of trimming or lower-casing them implicitly.
func (t Target) Validate() error {
	if !validHost(t.Host) {
		return ErrResourceNotAllowed
	}
	if t.Port <= 0 || t.Port > 65535 {
		return ErrResourceNotAllowed
	}
	if !validProtocol(t.Protocol) {
		return ErrResourceNotAllowed
	}
	return nil
}

func (t Target) valid() bool {
	return t.Validate() == nil
}
func (t Target) equal(o Target) bool { return t == o }

func safeNetworkToken(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validHost(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) || !safeNetworkToken(value) || len(value) > 253 {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	if strings.ContainsAny(value, "/?#@:*[]\\%") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || strings.Contains(value, "..") {
		return false
	}
	labels := strings.Split(value, ".")
	allNumeric := true
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
			if r < '0' || r > '9' {
				allNumeric = false
			}
		}
	}
	// Resolver APIs differ on shorthand numeric host forms (for example
	// "127.1"). Accept numeric labels only when ParseIP recognizes the
	// complete canonical address above; otherwise keep the target DNS-only.
	if allNumeric {
		return false
	}
	return true
}

func validProtocol(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 32 {
		return false
	}
	for i, r := range value {
		if (i == 0 && (r < 'a' || r > 'z')) || (i > 0 && !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.')) {
			return false
		}
	}
	return true
}

// ValidateTLSFingerprint accepts only the canonical lowercase SHA-256 form
// used by the broker (`sha256:<64 lowercase hex characters>`). A caller must
// not pass a certificate subject, URL, or a display label in this field.
func ValidateTLSFingerprint(value string) error {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return ErrInvalidLease
	}
	for _, r := range value[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return ErrInvalidLease
		}
	}
	return nil
}

// ResourceBinding gives a policy resource a stable logical ID. The ID is
// optional for legacy allowlists, but when supplied it is bound exactly to the
// host/port/protocol tuple and cannot be reused for another target.
type ResourceBinding struct {
	ID     string
	Target Target
}

type PolicySnapshot struct {
	Epoch     uint64
	Resources []ResourceBinding
}

type OfflinePolicy struct {
	internal    map[Target]struct{}
	hosts       map[string]struct{}
	resourceIDs map[string]Target
	epoch       uint64
}

func NewOfflinePolicy(resources []Resource) OfflinePolicy {
	return newOfflinePolicy(resources, nil, 0)
}

// NewOfflinePolicyWithEpoch creates an allowlist tied to a non-zero policy
// epoch. A lease issued against an older epoch is rejected after a policy
// change, even when the target itself is unchanged.
func NewOfflinePolicyWithEpoch(resources []Resource, epoch uint64) OfflinePolicy {
	return newOfflinePolicy(resources, nil, epoch)
}

// NewOfflinePolicyFromBindings creates an allowlist with logical resource IDs.
func NewOfflinePolicyFromBindings(bindings []ResourceBinding, epoch uint64) OfflinePolicy {
	resources := make([]Resource, 0, len(bindings))
	ids := make(map[string]Target, len(bindings))
	for _, binding := range bindings {
		if binding.ID != "" && !safeNetworkToken(binding.ID) {
			continue
		}
		resources = append(resources, binding.Target)
		if binding.ID != "" {
			if prior, exists := ids[binding.ID]; !exists || prior == binding.Target {
				ids[binding.ID] = binding.Target
			}
		}
	}
	return newOfflinePolicy(resources, ids, epoch)
}

func newOfflinePolicy(resources []Resource, ids map[string]Target, epoch uint64) OfflinePolicy {
	p := OfflinePolicy{internal: make(map[Target]struct{}, len(resources)), hosts: make(map[string]struct{}, len(resources)), resourceIDs: make(map[string]Target, len(ids)), epoch: epoch}
	for _, r := range resources {
		if r.valid() {
			p.internal[r] = struct{}{}
			p.hosts[r.Host] = struct{}{}
		}
	}
	for id, target := range ids {
		if id != "" && target.valid() {
			if _, exists := p.internal[target]; exists {
				p.resourceIDs[id] = target
			}
		}
	}
	return p
}

// Epoch returns the policy generation. Zero means this legacy policy is not
// epoch-bound and should only be used by compatibility adapters.
func (p OfflinePolicy) Epoch() uint64 { return p.epoch }

// Snapshot returns a defensive, deterministic policy description suitable for
// an approval or audit record. It performs no I/O.
func (p OfflinePolicy) Snapshot() PolicySnapshot {
	resources := make([]ResourceBinding, 0, len(p.internal))
	for target := range p.internal {
		ids := make([]string, 0)
		for candidateID, candidateTarget := range p.resourceIDs {
			if candidateTarget == target {
				ids = append(ids, candidateID)
			}
		}
		if len(ids) == 0 {
			resources = append(resources, ResourceBinding{Target: target})
			continue
		}
		for _, id := range ids {
			resources = append(resources, ResourceBinding{ID: id, Target: target})
		}
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].ID != resources[j].ID {
			return resources[i].ID < resources[j].ID
		}
		if resources[i].Target.Host != resources[j].Target.Host {
			return resources[i].Target.Host < resources[j].Target.Host
		}
		if resources[i].Target.Port != resources[j].Target.Port {
			return resources[i].Target.Port < resources[j].Target.Port
		}
		return resources[i].Target.Protocol < resources[j].Target.Protocol
	})
	return PolicySnapshot{Epoch: p.epoch, Resources: resources}
}

func (p OfflinePolicy) Check(t Target) error {
	if err := t.Validate(); err != nil {
		return ErrResourceNotAllowed
	}
	if _, ok := p.internal[t]; ok {
		return nil
	}
	if _, ok := p.hosts[t.Host]; ok {
		return ErrResourceNotAllowed
	}
	return fmt.Errorf("%w: %s:%d", ErrExternalEgressDenied, t.Host, t.Port)
}

// CheckAt applies both the exact allowlist and the policy epoch. It is the
// boundary a temporary-network broker should call before issuing a lease.
func (p OfflinePolicy) CheckAt(t Target, epoch uint64) error {
	if p.epoch != 0 && epoch != p.epoch {
		return ErrPolicyEpoch
	}
	return p.Check(t)
}

// CheckResource requires the caller to name the logical resource as well as
// the exact target tuple. This prevents a plugin from substituting another
// endpoint behind an approved resource name.
func (p OfflinePolicy) CheckResource(id string, t Target, epoch uint64) error {
	if !validOpaque(id, 256) {
		return ErrResourceNotAllowed
	}
	registered, ok := p.resourceIDs[id]
	if !ok || registered != t {
		return ErrResourceNotAllowed
	}
	if err := p.CheckAt(t, epoch); err != nil {
		return err
	}
	return nil
}

type IssueRequest struct {
	PluginID, PluginVersion string
	Target                  Target
	TLSFingerprint          string
	PolicyEpoch             uint64
	ConfirmationID          string
	TTL                     time.Duration
	// TemporaryEgress marks an exceptional external operation. Secure managers
	// otherwise permit only exact registered internal resources.
	TemporaryEgress bool
	// ResourceID is the logical policy resource. It is required when the
	// manager is configured with a resource-ID allowlist.
	ResourceID string
	// OperatorID identifies the administrator who approved this temporary
	// lease. It is intentionally an opaque identifier; raw passwords never
	// enter this package.
	OperatorID string
	// ConfirmationExpiresAt lets the control plane bind the approval to its
	// own expiry. Zero retains the legacy manager behavior.
	ConfirmationExpiresAt time.Time
	// MaxBytes is an optional hard cap. MaxRequests is hard-limited to one:
	// zero is normalized to one when the lease is issued.
	MaxBytes, MaxRequests int64
}
type RequestScope struct {
	PluginID, PluginVersion string
	Target                  Target
	TLSFingerprint          string
	PolicyEpoch             uint64
	ResourceID              string
	OperatorID              string
	TemporaryEgress         bool
}
type Lease struct {
	ID, PluginID, PluginVersion string
	Target                      Target
	TLSFingerprint              string
	PolicyEpoch                 uint64
	ConfirmationID              string
	ResourceID                  string
	OperatorID                  string
	IssuedAt, ExpiresAt         time.Time
	ConfirmationExpiresAt       time.Time
	TemporaryEgress             bool
	Revoked                     bool
	Consumed                    bool
	Completed                   bool
	LastResult                  string
	MaxBytes, MaxRequests       int64
	Bytes, Requests             int64
}
type AuditEvent struct {
	LeaseID, Action, PluginID, PluginVersion   string
	TargetHost, TargetProtocol, ConfirmationID string
	ResourceID, OperatorID, TLSFingerprint     string
	TargetPort                                 int
	PolicyEpoch                                uint64
	TemporaryEgress                            bool
	Bytes, BytesSent, BytesReceived, Requests  int64
	Result                                     string
	Reason                                     string
	At                                         time.Time
}

// Usage is non-payload accounting recorded after a socket attempt.
type Usage struct {
	BytesSent, BytesReceived int64
	Result                   string
}

// ConfirmationRequest is passed to an optional control-plane verifier. The
// verifier should validate a password/TOTP out of process and return only the
// result; this package never receives or stores the secret itself.
type ConfirmationRequest struct {
	ID, OperatorID, PluginID, PluginVersion, ResourceID string
	Target                                              Target
	TLSFingerprint                                      string
	PolicyEpoch                                         uint64
	TTL                                                 time.Duration
	ConfirmationExpiresAt                               time.Time
	TemporaryEgress                                     bool
	MaxBytes                                            int64
}

type ConfirmationVerifier func(ConfirmationRequest) error

type ManagerOptions struct {
	Now                  func() time.Time
	Policy               OfflinePolicy
	RequirePolicy        bool
	RequireConfirmation  bool
	ConsumeConfirmation  bool
	AllowTemporaryEgress bool
	ConfirmationVerifier ConfirmationVerifier
}

type Manager struct {
	// executionGate gives runtime brokers a linearization point between a
	// successful lease consume and the first network syscall. Policy updates and
	// revocations take the write side, so an update either happens before the
	// connection starts (and denies it) or after that already-authorized attempt
	// completes. The pure Manager APIs remain usable without this gate; runtime
	// code must use AcquireUse.
	executionGate        sync.RWMutex
	mu                   sync.Mutex
	now                  func() time.Time
	leases               map[string]Lease
	audit                []AuditEvent
	policy               OfflinePolicy
	requirePolicy        bool
	requireConfirmation  bool
	confirmationVerifier ConfirmationVerifier
	consumeConfirmation  bool
	allowTemporaryEgress bool
	confirmations        map[string]struct{}
}

func NewManager(now func() time.Time) *Manager {
	return NewManagerWithOptions(ManagerOptions{Now: now})
}

// NewManagerWithOptions creates a manager with explicit policy and approval
// controls. NewManager remains a compatibility constructor; production
// adapters should set RequirePolicy and RequireConfirmation.
func NewManagerWithOptions(opts ManagerOptions) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Manager{
		now: opts.Now, leases: make(map[string]Lease), policy: opts.Policy,
		requirePolicy: opts.RequirePolicy, requireConfirmation: opts.RequireConfirmation,
		confirmationVerifier: opts.ConfirmationVerifier, consumeConfirmation: opts.ConsumeConfirmation,
		allowTemporaryEgress: opts.AllowTemporaryEgress,
		confirmations:        make(map[string]struct{}),
	}
}

// NewSecureManager is the recommended constructor for offline plugin brokers:
// ordinary leases require an exact registered resource and policy epoch; an
// explicitly marked temporary external lease additionally requires the
// approval verifier.
func NewSecureManager(policy OfflinePolicy, now func() time.Time, verifier ConfirmationVerifier) *Manager {
	return NewManagerWithOptions(ManagerOptions{Now: now, Policy: policy, RequirePolicy: true, ConsumeConfirmation: true, AllowTemporaryEgress: true, ConfirmationVerifier: verifier})
}

// UpdatePolicy publishes a new immutable policy generation. Existing leases
// bound to a prior epoch fail closed on their next authorization check.
func (m *Manager) UpdatePolicy(policy OfflinePolicy) error {
	if policy.epoch == 0 {
		return ErrPolicyEpoch
	}
	m.executionGate.Lock()
	defer m.executionGate.Unlock()
	m.mu.Lock()
	if m.requirePolicy && m.policy.epoch != 0 && policy.epoch <= m.policy.epoch {
		m.mu.Unlock()
		return ErrPolicyEpoch
	}
	m.policy = policy
	m.requirePolicy = true
	m.mu.Unlock()
	return nil
}

// PolicySnapshot returns the currently published policy without exposing its
// internal maps.
func (m *Manager) PolicySnapshot() PolicySnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.policy.Snapshot()
}
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (m *Manager) Issue(r IssueRequest) (Lease, error) {
	m.mu.Lock()
	requirePolicy, requireConfirmation := m.requirePolicy, m.requireConfirmation
	confirmationVerifier, allowTemporaryEgress := m.confirmationVerifier, m.allowTemporaryEgress
	consumeConfirmation := m.consumeConfirmation
	m.mu.Unlock()
	if !validOpaque(r.PluginID, 256) || !validOpaque(r.PluginVersion, 128) || r.Target.Validate() != nil || !validOpaque(r.TLSFingerprint, 256) || r.PolicyEpoch == 0 || !validOpaque(r.ConfirmationID, 256) || r.TTL <= 0 {
		return Lease{}, ErrInvalidLease
	}
	if (requirePolicy || r.TemporaryEgress) && ValidateTLSFingerprint(r.TLSFingerprint) != nil {
		return Lease{}, ErrInvalidLease
	}
	if (r.ResourceID != "" && !validOpaque(r.ResourceID, 256)) || (r.OperatorID != "" && !validOpaque(r.OperatorID, 128)) {
		return Lease{}, ErrInvalidLease
	}
	if r.TTL > MaxLeaseTTL {
		return Lease{}, ErrLeaseTTL
	}
	if r.MaxBytes < 0 || r.MaxRequests < 0 || r.MaxRequests > 1 {
		return Lease{}, ErrInvalidLease
	}
	now := m.now()
	if !r.ConfirmationExpiresAt.IsZero() && !now.Before(r.ConfirmationExpiresAt) {
		return Lease{}, ErrConfirmationExpired
	}
	m.mu.Lock()
	policy := m.policy
	m.mu.Unlock()
	if requirePolicy {
		if err := checkIssuePolicy(policy, r, allowTemporaryEgress); err != nil {
			return Lease{}, err
		}
	}
	if r.TemporaryEgress && !allowTemporaryEgress {
		return Lease{}, ErrTemporaryEgressDenied
	}
	if r.TemporaryEgress && (!validOpaque(r.OperatorID, 128) || confirmationVerifier == nil) {
		return Lease{}, ErrConfirmationRequired
	}
	if requireConfirmation {
		if !validOpaque(r.OperatorID, 128) || confirmationVerifier == nil {
			return Lease{}, ErrConfirmationRequired
		}
	}
	verifyConfirmation := confirmationVerifier != nil && (requireConfirmation || r.TemporaryEgress)
	if verifyConfirmation {
		if consumeConfirmation {
			m.mu.Lock()
			_, used := m.confirmations[r.ConfirmationID]
			m.mu.Unlock()
			if used {
				return Lease{}, ErrConfirmationReplay
			}
		}
		if err := confirmationVerifier(ConfirmationRequest{ID: r.ConfirmationID, OperatorID: r.OperatorID, PluginID: r.PluginID, PluginVersion: r.PluginVersion, ResourceID: r.ResourceID, Target: r.Target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: r.PolicyEpoch, TTL: r.TTL, ConfirmationExpiresAt: r.ConfirmationExpiresAt, TemporaryEgress: r.TemporaryEgress, MaxBytes: r.MaxBytes}); err != nil {
			return Lease{}, fmt.Errorf("%w: %v", ErrConfirmationRequired, err)
		}
	}
	id, err := newID()
	if err != nil {
		return Lease{}, err
	}
	expiresAt := now.Add(r.TTL)
	if !r.ConfirmationExpiresAt.IsZero() && r.ConfirmationExpiresAt.Before(expiresAt) {
		expiresAt = r.ConfirmationExpiresAt
	}
	maxRequests := r.MaxRequests
	if maxRequests == 0 {
		maxRequests = 1
	}
	l := Lease{ID: id, PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: r.Target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: r.PolicyEpoch, ConfirmationID: r.ConfirmationID, ResourceID: r.ResourceID, OperatorID: r.OperatorID, IssuedAt: now, ExpiresAt: expiresAt, ConfirmationExpiresAt: r.ConfirmationExpiresAt, TemporaryEgress: r.TemporaryEgress, MaxBytes: r.MaxBytes, MaxRequests: maxRequests}
	m.mu.Lock()
	if m.requirePolicy && m.policy.epoch != r.PolicyEpoch {
		m.mu.Unlock()
		return Lease{}, ErrPolicyEpoch
	}
	if m.requirePolicy {
		if err := checkIssuePolicy(m.policy, r, m.allowTemporaryEgress); err != nil {
			m.mu.Unlock()
			return Lease{}, err
		}
	}
	if consumeConfirmation && verifyConfirmation {
		if _, used := m.confirmations[r.ConfirmationID]; used {
			m.mu.Unlock()
			return Lease{}, ErrConfirmationReplay
		}
		m.confirmations[r.ConfirmationID] = struct{}{}
	}
	m.leases[id] = l
	m.audit = append(m.audit, m.eventLocked(l, "issued", 0, 0, "issued", now))
	m.mu.Unlock()
	return l, nil
}

func checkIssuePolicy(policy OfflinePolicy, r IssueRequest, allowTemporaryEgress bool) error {
	if policy.epoch == 0 {
		return ErrPolicyEpoch
	}
	if len(policy.resourceIDs) > 0 && r.ResourceID == "" && !r.TemporaryEgress {
		return ErrResourceNotAllowed
	}
	var policyErr error
	if r.ResourceID != "" {
		policyErr = policy.CheckResource(r.ResourceID, r.Target, r.PolicyEpoch)
	} else {
		policyErr = policy.CheckAt(r.Target, r.PolicyEpoch)
	}
	if len(policy.resourceIDs) > 0 && r.ResourceID == "" && policyErr == nil {
		return ErrResourceNotAllowed
	}
	if policyErr != nil && r.TemporaryEgress && r.ResourceID != "" && errors.Is(policyErr, ErrExternalEgressDenied) {
		return ErrResourceNotAllowed
	}
	if policyErr != nil && !(r.TemporaryEgress && allowTemporaryEgress && errors.Is(policyErr, ErrExternalEgressDenied)) {
		return policyErr
	}
	return nil
}

// IssueTemporary is the explicit API for a one-off outbound operation. It
// cannot bypass the secure manager's policy or confirmation verifier.
func (m *Manager) IssueTemporary(r IssueRequest) (Lease, error) {
	r.TemporaryEgress = true
	return m.Issue(r)
}
func (m *Manager) Authorize(l Lease, s RequestScope) error {
	now := m.now()
	m.mu.Lock()
	stored, err := m.validateLocked(l.ID, s, now)
	if err != nil {
		m.audit = append(m.audit, m.eventForScope(l.ID, s, "authorization_denied", err.Error(), now))
		m.mu.Unlock()
		return err
	}
	if stored.Consumed {
		m.audit = append(m.audit, m.eventLocked(stored, "authorization_denied", 0, stored.Requests, ErrLeaseConsumed.Error(), now))
		m.mu.Unlock()
		return ErrLeaseConsumed
	}
	m.audit = append(m.audit, m.eventLocked(stored, "authorized", 0, 0, "authorized", now))
	m.mu.Unlock()
	return nil
}

// Consume atomically spends a lease for one socket/connection attempt.
// Authorize is intentionally a non-consuming preflight for compatibility; a
// runtime broker must call Consume immediately before opening its socket.
func (m *Manager) Consume(l Lease, s RequestScope) error {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.consumeLocked(l.ID, s, now)
	return err
}

// AcquireUse atomically consumes a one-shot lease and holds the runtime
// execution gate until the returned release function is called. A network
// broker must call it immediately before resolving/dialing so revocation and
// policy updates cannot slip between authorization and the first connection
// attempt. Call release exactly once, including on every error path.
func (m *Manager) AcquireUse(id string, s RequestScope) (Lease, func(), error) {
	if m == nil {
		return Lease{}, nil, ErrInvalidLease
	}
	m.executionGate.RLock()
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			m.executionGate.RUnlock()
		})
	}
	now := m.now()
	m.mu.Lock()
	stored, err := m.consumeLocked(id, s, now)
	m.mu.Unlock()
	if err != nil {
		release()
		return Lease{}, nil, err
	}
	return stored, release, nil
}

func (m *Manager) consumeLocked(id string, s RequestScope, now time.Time) (Lease, error) {
	stored, err := m.validateLocked(id, s, now)
	if err != nil {
		m.audit = append(m.audit, m.eventForScope(id, s, "consume_denied", err.Error(), now))
		return Lease{}, err
	}
	if stored.Consumed || (stored.MaxRequests > 0 && stored.Requests >= stored.MaxRequests) {
		if stored.Consumed {
			m.audit = append(m.audit, m.eventLocked(stored, "consume_denied", 0, stored.Requests, ErrLeaseConsumed.Error(), now))
			return Lease{}, ErrLeaseConsumed
		}
		m.audit = append(m.audit, m.eventLocked(stored, "consume_denied", 0, stored.Requests, ErrUsageLimit.Error(), now))
		return Lease{}, ErrUsageLimit
	}
	stored.Consumed = true
	stored.Requests++
	m.leases[stored.ID] = stored
	m.audit = append(m.audit, m.eventLocked(stored, "consumed", 0, stored.Requests, "consumed", now))
	return stored, nil
}

// AuthorizeOnce is an explicit alias for Consume for adapters that model a
// lease as a single authorization operation.
func (m *Manager) AuthorizeOnce(l Lease, s RequestScope) error {
	return m.Consume(l, s)
}

// RecordUsage records bytes and the final connection result without recording
// payload contents. It enforces optional per-lease byte/request caps.
func (m *Manager) RecordUsage(l Lease, s RequestScope, bytes int64, result string) error {
	if bytes < 0 || !safeAuditToken(result) {
		return ErrInvalidLease
	}
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, err := m.validateLocked(l.ID, s, now)
	if err != nil {
		m.audit = append(m.audit, m.eventForScope(l.ID, s, "result_denied", err.Error(), now))
		return err
	}
	if !stored.Consumed {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", 0, stored.Requests, ErrLeaseNotConsumed.Error(), now))
		return ErrLeaseNotConsumed
	}
	if stored.Completed {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", 0, stored.Requests, ErrLeaseConsumed.Error(), now))
		return ErrLeaseConsumed
	}
	if stored.MaxBytes > 0 && stored.Bytes > stored.MaxBytes-bytes {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", bytes, stored.Requests, ErrUsageLimit.Error(), now))
		return ErrUsageLimit
	}
	stored.Bytes += bytes
	stored.Completed = true
	stored.LastResult = result
	m.leases[stored.ID] = stored
	m.audit = append(m.audit, m.eventLocked(stored, "result", bytes, stored.Requests, result, now))
	return nil
}

// RecordTransfer records directional byte counters without retaining payloads.
// It is the preferred API when the transport can distinguish sent and received
// bytes; RecordUsage remains a compatibility shorthand for a single counter.
func (m *Manager) RecordTransfer(l Lease, s RequestScope, usage Usage) error {
	if usage.BytesSent < 0 || usage.BytesReceived < 0 || usage.BytesSent > int64(^uint64(0)>>1)-usage.BytesReceived || !safeAuditToken(usage.Result) {
		return ErrInvalidLease
	}
	total := usage.BytesSent + usage.BytesReceived
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, err := m.validateLocked(l.ID, s, now)
	if err != nil {
		m.audit = append(m.audit, m.eventForScope(l.ID, s, "result_denied", err.Error(), now))
		return err
	}
	if !stored.Consumed {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", 0, stored.Requests, ErrLeaseNotConsumed.Error(), now))
		return ErrLeaseNotConsumed
	}
	if stored.Completed {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", 0, stored.Requests, ErrLeaseConsumed.Error(), now))
		return ErrLeaseConsumed
	}
	if stored.MaxBytes > 0 && stored.Bytes > stored.MaxBytes-total {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", total, stored.Requests, ErrUsageLimit.Error(), now))
		return ErrUsageLimit
	}
	stored.Bytes += total
	stored.Completed = true
	stored.LastResult = usage.Result
	m.leases[stored.ID] = stored
	event := m.eventLocked(stored, "result", total, stored.Requests, usage.Result, now)
	event.BytesSent = usage.BytesSent
	event.BytesReceived = usage.BytesReceived
	m.audit = append(m.audit, event)
	return nil
}

// RecordTransferFinal records the outcome of an attempt that has already
// crossed the runtime network boundary through AcquireUse. Unlike
// RecordTransfer, it deliberately permits final accounting after the lease
// TTL, policy epoch, or revocation has changed: those controls stop future
// attempts, while suppressing the result of an already-started attempt would
// create an audit gap. Scope, consumed state, byte limits, and one-result-only
// semantics remain enforced.
func (m *Manager) RecordTransferFinal(l Lease, s RequestScope, usage Usage) error {
	if usage.BytesSent < 0 || usage.BytesReceived < 0 || usage.BytesSent > int64(^uint64(0)>>1)-usage.BytesReceived || !safeAuditToken(usage.Result) {
		return ErrInvalidLease
	}
	total := usage.BytesSent + usage.BytesReceived
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.leases[l.ID]
	if !ok {
		m.audit = append(m.audit, m.eventForScope(l.ID, s, "result_denied", ErrInvalidLease.Error(), now))
		return ErrInvalidLease
	}
	if !leaseMatchesScope(stored, s) {
		m.audit = append(m.audit, m.eventForScope(l.ID, s, "result_denied", ErrLeaseScope.Error(), now))
		return ErrLeaseScope
	}
	if !stored.Consumed {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", 0, stored.Requests, ErrLeaseNotConsumed.Error(), now))
		return ErrLeaseNotConsumed
	}
	if stored.Completed {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", 0, stored.Requests, ErrLeaseConsumed.Error(), now))
		return ErrLeaseConsumed
	}
	if stored.MaxBytes > 0 && stored.Bytes > stored.MaxBytes-total {
		m.audit = append(m.audit, m.eventLocked(stored, "result_denied", total, stored.Requests, ErrUsageLimit.Error(), now))
		return ErrUsageLimit
	}
	stored.Bytes += total
	stored.Completed = true
	stored.LastResult = usage.Result
	m.leases[stored.ID] = stored
	event := m.eventLocked(stored, "result", total, stored.Requests, usage.Result, now)
	event.BytesSent = usage.BytesSent
	event.BytesReceived = usage.BytesReceived
	m.audit = append(m.audit, event)
	return nil
}

func safeAuditToken(value string) bool {
	return value != "" && safeNetworkToken(value) && len(value) <= 128
}

func validOpaque(value string, max int) bool {
	return value != "" && len(value) <= max && safeNetworkToken(value)
}

func (m *Manager) validateLocked(id string, s RequestScope, now time.Time) (Lease, error) {
	stored, ok := m.leases[id]
	if !ok {
		return Lease{}, ErrInvalidLease
	}
	if stored.Revoked {
		return Lease{}, ErrLeaseRevoked
	}
	if !stored.ConfirmationExpiresAt.IsZero() && !now.Before(stored.ConfirmationExpiresAt) {
		return Lease{}, ErrConfirmationExpired
	}
	if !now.Before(stored.ExpiresAt) {
		return Lease{}, ErrLeaseExpired
	}
	if m.requirePolicy && m.policy.epoch != 0 && stored.PolicyEpoch != m.policy.epoch {
		return Lease{}, fmt.Errorf("%w: %w", ErrLeaseScope, ErrPolicyEpoch)
	}
	if !leaseMatchesScope(stored, s) {
		return Lease{}, ErrLeaseScope
	}
	return stored, nil
}

func leaseMatchesScope(stored Lease, s RequestScope) bool {
	return stored.PluginID == s.PluginID &&
		stored.PluginVersion == s.PluginVersion &&
		stored.Target.equal(s.Target) &&
		stored.TLSFingerprint == s.TLSFingerprint &&
		stored.PolicyEpoch == s.PolicyEpoch &&
		stored.ResourceID == s.ResourceID &&
		stored.OperatorID == s.OperatorID &&
		stored.TemporaryEgress == s.TemporaryEgress
}

func (m *Manager) eventLocked(l Lease, action string, bytes, requests int64, result string, at time.Time) AuditEvent {
	return AuditEvent{LeaseID: l.ID, Action: action, PluginID: l.PluginID, PluginVersion: l.PluginVersion, TargetHost: l.Target.Host, TargetPort: l.Target.Port, TargetProtocol: l.Target.Protocol, TLSFingerprint: l.TLSFingerprint, PolicyEpoch: l.PolicyEpoch, TemporaryEgress: l.TemporaryEgress, ConfirmationID: l.ConfirmationID, ResourceID: l.ResourceID, OperatorID: l.OperatorID, Bytes: bytes, Requests: requests, Result: result, Reason: result, At: at}
}

func (m *Manager) eventForScope(leaseID string, s RequestScope, action, result string, at time.Time) AuditEvent {
	return AuditEvent{LeaseID: leaseID, Action: action, PluginID: s.PluginID, PluginVersion: s.PluginVersion, TargetHost: s.Target.Host, TargetPort: s.Target.Port, TargetProtocol: s.Target.Protocol, TLSFingerprint: s.TLSFingerprint, PolicyEpoch: s.PolicyEpoch, TemporaryEgress: s.TemporaryEgress, ResourceID: s.ResourceID, OperatorID: s.OperatorID, Result: result, Reason: result, At: at}
}
func (m *Manager) Revoke(id string) error {
	now := m.now()
	m.executionGate.Lock()
	defer m.executionGate.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.leases[id]
	if !ok {
		return ErrInvalidLease
	}
	if !l.Revoked {
		l.Revoked = true
		m.leases[id] = l
		m.audit = append(m.audit, m.eventLocked(l, "revoked", 0, l.Requests, "revoked", now))
	}
	return nil
}

// Get returns a defensive lease snapshot for an adapter or audit view.
func (m *Manager) Get(id string) (Lease, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.leases[id]
	return l, ok
}
func (m *Manager) Audit() []AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AuditEvent(nil), m.audit...)
}
