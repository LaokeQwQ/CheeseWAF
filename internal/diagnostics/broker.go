// Package diagnostics defines the in-process contract for diagnostic uploads.
// It deliberately has no network, filesystem, key, SQL, or cache dependency.
package diagnostics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const SchemaVersion = "diagnostic.v1"

var (
	ErrInvalidRequest          = errors.New("invalid diagnostic upload request")
	ErrForbiddenField          = errors.New("diagnostic package contains a forbidden field")
	ErrRawConfirmationRequired = errors.New("raw diagnostic upload requires high-risk confirmation")
	ErrQueueFull               = errors.New("diagnostic queue is full")
	ErrByteQuota               = errors.New("diagnostic byte quota exceeded")
	ErrIdempotencyConflict     = errors.New("diagnostic idempotency key is bound to a different request")
	ErrNotFound                = errors.New("diagnostic upload not found")
	ErrExpired                 = errors.New("diagnostic upload expired")
	ErrInvalidState            = errors.New("invalid diagnostic upload state")
	ErrAttemptsExceeded        = errors.New("diagnostic upload retry attempts exceeded")
)

type Kind string

const (
	KindMetadata  Kind = "metadata"
	KindHealth    Kind = "health"
	KindSanitized Kind = "sanitized"
	KindRaw       Kind = "raw"
)

// Package is deliberately fixed-schema; arbitrary request bodies are not representable.
type Package struct {
	Kind     Kind              `json:"kind"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Health   map[string]string `json:"health,omitempty"`
	Findings []Finding         `json:"findings,omitempty"`
}
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message,omitempty"`
}

// DecodePackage strictly decodes the fixed diagnostic.v1 payload. It rejects
// unknown fields and trailing JSON so an integration cannot silently discard
// data outside the contract.
func DecodePackage(raw []byte) (Package, error) {
	var p Package
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Package{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Package{}, fmt.Errorf("%w: trailing JSON", ErrInvalidRequest)
	}
	if !validKind(p.Kind) {
		return Package{}, ErrInvalidRequest
	}
	if err := scanForbidden(p); err != nil {
		return Package{}, err
	}
	return p, nil
}

type Request struct {
	Package                                                    Package
	Target, PluginID, PluginVersion                            string
	PolicyEpoch                                                uint64
	LeaseID, IdempotencyKey, ConfirmationID                    string
	PasswordConfirmed, FinalConfirmation, HighRiskAcknowledged bool
}
type Config struct {
	MaxQueueItems   int
	MaxQueueBytes   int64
	MaxHistoryItems int
	TTL             time.Duration
	MaxAttempts     int
	Now             func() time.Time
}
type State string

const (
	StateQueued    State = "queued"
	StateUploading State = "uploading"
	StateRetrying  State = "retrying"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateExpired   State = "expired"
)

type Receipt struct {
	UploadID      string
	State         State
	ExpiresAt     time.Time
	SchemaVersion string
}
type Status struct {
	UploadID                                   string
	State                                      State
	Attempt, MaxAttempts                       int
	Bytes                                      int64
	ExpiresAt                                  time.Time
	LastError, Target, PluginID, PluginVersion string
	PolicyEpoch                                uint64
}
type Item struct {
	UploadID                                 string
	Package                                  Package
	Target, PluginID, PluginVersion, LeaseID string
	PolicyEpoch                              uint64
	Attempt                                  int
	Bytes                                    int64
}
type record struct {
	item               Item
	state              State
	expiresAt          time.Time
	retainedUntil      time.Time
	lastError, binding string
	idempotencyKey     string
	queued             bool
	accounted, active  bool
	maxAttempts        int
}
type Broker struct {
	mu          sync.Mutex
	cfg         Config
	seq         atomic.Uint64
	records     map[string]*record
	idempotency map[string]string
	queue       []string
	history     []string
	bytes       int64
	active      int
}

func NewBroker(cfg Config) (*Broker, error) {
	if cfg.MaxQueueItems <= 0 {
		cfg.MaxQueueItems = 128
	}
	if cfg.MaxHistoryItems <= 0 {
		cfg.MaxHistoryItems = cfg.MaxQueueItems * 2
	}
	if cfg.MaxQueueBytes <= 0 {
		cfg.MaxQueueBytes = 16 << 20
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.MaxAttempts > 3 {
		return nil, ErrInvalidRequest
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Broker{cfg: cfg, records: map[string]*record{}, idempotency: map[string]string{}}, nil
}
func (b *Broker) Submit(ctx context.Context, req Request) (Receipt, error) {
	if b == nil {
		return Receipt{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if err := validateRequest(req); err != nil {
		return Receipt{}, err
	}
	binding, n, err := canonicalBinding(req)
	if err != nil {
		return Receipt{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	if id, ok := b.idempotency[req.IdempotencyKey]; ok {
		r := b.records[id]
		if r == nil {
			delete(b.idempotency, req.IdempotencyKey)
		} else if r.state == StateExpired {
			return Receipt{}, ErrExpired
		} else if r.binding != binding {
			return Receipt{}, ErrIdempotencyConflict
		} else {
			return receiptOf(r), nil
		}
	}
	if b.active >= b.cfg.MaxQueueItems {
		return Receipt{}, ErrQueueFull
	}
	if n > b.cfg.MaxQueueBytes-b.bytes {
		return Receipt{}, ErrByteQuota
	}
	id := fmt.Sprintf("upload-%d", b.seq.Add(1))
	maxAttempts := b.cfg.MaxAttempts
	if req.Package.Kind == KindRaw && maxAttempts > 2 {
		maxAttempts = 2
	}
	now := b.cfg.Now().UTC()
	r := &record{item: Item{UploadID: id, Package: clonePackage(req.Package), Target: req.Target, PluginID: req.PluginID, PluginVersion: req.PluginVersion, LeaseID: req.LeaseID, PolicyEpoch: req.PolicyEpoch, Bytes: n}, state: StateQueued, expiresAt: now.Add(b.cfg.TTL), binding: binding, idempotencyKey: req.IdempotencyKey, queued: true, accounted: true, active: true, maxAttempts: maxAttempts}
	b.records[id] = r
	b.idempotency[req.IdempotencyKey] = id
	b.queue = append(b.queue, id)
	b.bytes += n
	b.active++
	return receiptOf(r), nil
}
func (b *Broker) Next() (Item, bool) {
	if b == nil {
		return Item{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	for len(b.queue) > 0 {
		id := b.queue[0]
		b.queue = b.queue[1:]
		r := b.records[id]
		if r == nil || !r.queued || r.state == StateExpired {
			continue
		}
		r.queued = false
		r.state = StateUploading
		r.item.Attempt++
		return cloneItem(r.item), true
	}
	return Item{}, false
}
func (b *Broker) Status(id string) (Status, error) {
	if b == nil {
		return Status{}, ErrNotFound
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	r, ok := b.records[strings.TrimSpace(id)]
	if !ok {
		return Status{}, ErrNotFound
	}
	if r.state == StateExpired {
		return Status{}, ErrExpired
	}
	return Status{UploadID: r.item.UploadID, State: r.state, Attempt: r.item.Attempt, MaxAttempts: r.maxAttempts, Bytes: r.item.Bytes, ExpiresAt: r.expiresAt, LastError: r.lastError, Target: r.item.Target, PluginID: r.item.PluginID, PluginVersion: r.item.PluginVersion, PolicyEpoch: r.item.PolicyEpoch}, nil
}
func (b *Broker) Retry(id string) error {
	if b == nil {
		return ErrNotFound
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	r, ok := b.records[strings.TrimSpace(id)]
	if !ok {
		return ErrNotFound
	}
	if r.state == StateExpired {
		return ErrExpired
	}
	if r.state != StateRetrying {
		return ErrInvalidState
	}
	if len(b.queue) >= b.cfg.MaxQueueItems {
		return ErrQueueFull
	}
	if !r.accounted && b.bytes+r.item.Bytes > b.cfg.MaxQueueBytes {
		return ErrByteQuota
	}
	r.state = StateQueued
	r.queued = true
	if !r.accounted {
		r.accounted = true
		b.bytes += r.item.Bytes
	}
	b.queue = append(b.queue, id)
	return nil
}
func (b *Broker) Complete(id string, success bool) error {
	if b == nil {
		return ErrNotFound
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.expireLocked()
	r, ok := b.records[strings.TrimSpace(id)]
	if !ok {
		return ErrNotFound
	}
	if r.state == StateExpired {
		return ErrExpired
	}
	if r.state != StateUploading {
		return ErrInvalidState
	}
	if success {
		b.finishLocked(r, StateCompleted)
		return nil
	}
	r.lastError = "worker reported failure"
	if r.item.Attempt >= r.maxAttempts {
		b.finishLocked(r, StateFailed)
		return ErrAttemptsExceeded
	}
	r.state = StateRetrying
	return nil
}
func validateRequest(q Request) error {
	if !validKind(q.Package.Kind) || strings.TrimSpace(q.Target) == "" || strings.TrimSpace(q.PluginID) == "" || strings.TrimSpace(q.PluginVersion) == "" || q.PolicyEpoch == 0 || strings.TrimSpace(q.LeaseID) == "" || strings.TrimSpace(q.IdempotencyKey) == "" {
		return ErrInvalidRequest
	}
	if q.Package.Kind == KindRaw && (!q.HighRiskAcknowledged || strings.TrimSpace(q.ConfirmationID) == "" || !q.PasswordConfirmed || !q.FinalConfirmation) {
		return ErrRawConfirmationRequired
	}
	return scanForbidden(q.Package)
}
func validKind(k Kind) bool {
	return k == KindMetadata || k == KindHealth || k == KindSanitized || k == KindRaw
}

var forbidden = []string{"secret", "token", "cookie", "authorization", "session", "origin", "credential", "password", "private_key", "privatekey", "request_body", "raw_request", "body"}

func scanForbidden(p Package) error {
	check := func(k string) bool {
		k = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(k, "-", "_"), " ", "_"))
		for _, f := range forbidden {
			if k == f || strings.Contains(k, f) {
				return true
			}
		}
		return false
	}
	for k, v := range p.Metadata {
		if check(k) || check(v) {
			return fmt.Errorf("%w: %s", ErrForbiddenField, k)
		}
	}
	for k, v := range p.Health {
		if check(k) || check(v) {
			return fmt.Errorf("%w: %s", ErrForbiddenField, k)
		}
	}
	for _, f := range p.Findings {
		if check(f.Code) || check(f.Message) || check(f.Severity) {
			return fmt.Errorf("%w: finding", ErrForbiddenField)
		}
	}
	return nil
}
func canonicalBinding(q Request) (string, int64, error) {
	v, err := json.Marshal(struct {
		Package                                  Package `json:"package"`
		Target, PluginID, PluginVersion, LeaseID string
		PolicyEpoch                              uint64
	}{q.Package, q.Target, q.PluginID, q.PluginVersion, q.LeaseID, q.PolicyEpoch})
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(v)
	return hex.EncodeToString(h[:]), int64(len(v)), nil
}
func receiptOf(r *record) Receipt {
	return Receipt{UploadID: r.item.UploadID, State: r.state, ExpiresAt: r.expiresAt, SchemaVersion: SchemaVersion}
}
func clonePackage(p Package) Package {
	q := p
	q.Metadata = cloneMap(p.Metadata)
	q.Health = cloneMap(p.Health)
	q.Findings = append([]Finding(nil), p.Findings...)
	return q
}
func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	q := make(map[string]string, len(m))
	for k, v := range m {
		q[k] = v
	}
	return q
}
func cloneItem(i Item) Item { i.Package = clonePackage(i.Package); return i }
func (b *Broker) expireLocked() {
	now := b.cfg.Now().UTC()
	for id, r := range b.records {
		if r.state != StateCompleted && r.state != StateFailed && r.state != StateExpired && !now.Before(r.expiresAt) {
			b.finishLocked(r, StateExpired)
		}
		if (r.state == StateCompleted || r.state == StateFailed || r.state == StateExpired) && !now.Before(r.retainedUntil) {
			b.dropRecordLocked(id)
		}
	}
	b.compactQueueLocked()
}

func (b *Broker) finishLocked(r *record, state State) {
	if r.state == StateCompleted || r.state == StateFailed || r.state == StateExpired {
		return
	}
	now := b.cfg.Now().UTC()
	r.state, r.queued = state, false
	if r.active {
		r.active = false
		b.active--
	}
	if r.accounted {
		b.bytes -= r.item.Bytes
		r.accounted = false
	}
	r.item.Package = Package{}
	r.retainedUntil = r.expiresAt
	if !now.Before(r.retainedUntil) {
		r.retainedUntil = now.Add(time.Minute)
	}
	b.history = append(b.history, r.item.UploadID)
	for len(b.history) > b.cfg.MaxHistoryItems {
		b.dropRecordLocked(b.history[0])
		b.history = b.history[1:]
	}
}

func (b *Broker) dropRecordLocked(id string) {
	r, ok := b.records[id]
	if !ok {
		return
	}
	delete(b.records, id)
	if r.idempotencyKey != "" && b.idempotency[r.idempotencyKey] == id {
		delete(b.idempotency, r.idempotencyKey)
	}
}

func (b *Broker) compactQueueLocked() {
	kept := b.queue[:0]
	for _, id := range b.queue {
		if r := b.records[id]; r != nil && r.queued && r.state == StateQueued {
			kept = append(kept, id)
		}
	}
	b.queue = kept
}
