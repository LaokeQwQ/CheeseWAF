package extensions

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
)

const (
	RiskHintAPIVersion       = "cheesewaf/risk-hint/v1"
	SecurityEventAPIVersion  = "cheesewaf/security-event/v1"
	AnalysisRecordAPIVersion = "cheesewaf/analysis-record/v1"
	DefaultIngressQueueSize  = 64
	MaxIngressQueueSize      = 65536
	MaxOutputDataSize        = 64 << 10
	// defaultSeenRetention bounds how long a successful receipt stays
	// replayable. Sequence checks reject anything older regardless.
	defaultSeenRetention = 30 * time.Minute
	minSeenCapacity      = 1024
	ingressAppendTimeout = 10 * time.Second
	ingressCloseTimeout  = 10 * time.Second
)

var (
	ErrIngressConfig       = errors.New("invalid extension output ingress configuration")
	ErrOutputRejected      = errors.New("extension output rejected")
	ErrIngressReplay       = errors.New("extension output replay conflicts with accepted output")
	ErrIngressSequenceGap  = errors.New("extension output sequence has a gap")
	ErrIngressSequenceOld  = errors.New("extension output sequence is stale")
	ErrIngressQueueFull    = errors.New("extension output ingress queue is full")
	ErrIngressClosed       = errors.New("extension output ingress is closed")
	ErrIngressAuditFailed  = errors.New("extension output audit append failed")
	ErrIngressCloseTimeout = errors.New("extension output ingress close timed out")
)

// OutputClaims is the bounded envelope shared by Jev, EDR, and DuckDB
// outputs. Extension-specific fields belong under Data and are never sent to
// the audit runtime.
type OutputClaims struct {
	APIVersion    string          `json:"api_version"`
	PluginID      string          `json:"plugin_id"`
	PluginVersion string          `json:"plugin_version"`
	EventID       string          `json:"event_id"`
	Sequence      uint64          `json:"sequence"`
	TenantRef     string          `json:"tenant_ref"`
	SiteRef       string          `json:"site_ref"`
	PolicyEpoch   uint64          `json:"policy_epoch"`
	ObservedAt    time.Time       `json:"observed_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Data          json.RawMessage `json:"data,omitempty"`
}

func decodeOutputClaims(payload []byte) (OutputClaims, error) {
	if len(payload) == 0 || len(payload) > 1<<20 {
		return OutputClaims{}, ErrOutputRejected
	}
	var claims OutputClaims
	if err := decodeStrict(payload, &claims); err != nil {
		return OutputClaims{}, ErrOutputRejected
	}
	if len(claims.Data) > MaxOutputDataSize {
		return OutputClaims{}, ErrOutputRejected
	}
	if claims.Data != nil && string(claims.Data) == "null" {
		return OutputClaims{}, ErrOutputRejected
	}
	if !validAPIVersion(claims.APIVersion) || !validID(claims.PluginID) || !validID(claims.PluginVersion) || !validID(claims.EventID) || claims.Sequence == 0 || claims.PolicyEpoch == 0 || !validID(claims.TenantRef) || !validID(claims.SiteRef) || claims.ObservedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.ObservedAt) {
		return OutputClaims{}, ErrOutputRejected
	}
	return claims, nil
}

func validAPIVersion(value string) bool {
	switch value {
	case RiskHintAPIVersion, SecurityEventAPIVersion, AnalysisRecordAPIVersion:
		return true
	default:
		return false
	}
}

// OutputSink is the only side effect exposed by Ingress. Implementations
// should enqueue into the audit runtime; no ACL, policy, or request path is
// reachable from this contract.
type OutputSink interface {
	Append(context.Context, audit.Event) (audit.Record, error)
}

type OutputSinkFunc func(context.Context, audit.Event) (audit.Record, error)

func (f OutputSinkFunc) Append(ctx context.Context, event audit.Event) (audit.Record, error) {
	if f == nil {
		return audit.Record{}, ErrIngressConfig
	}
	return f(ctx, event)
}

type IngressOptions struct {
	Keys          map[string]TrustKey
	PluginID      string
	PluginVersion string
	TenantRef     string
	SiteRef       string
	PolicyEpoch   uint64
	MaxTTL        time.Duration
	ClockSkew     time.Duration
	StreamID      string
	QueueCapacity int
	Now           func() time.Time
	Sink          OutputSink
}

type Receipt struct {
	EventID       string
	Sequence      uint64
	PluginID      string
	PluginVersion string
	PayloadDigest string
	Duplicate     bool
}

type ingressEntry struct {
	digest  string
	event   audit.Event
	at      time.Time
	pending bool
	failed  bool
}

type queuedOutput struct {
	key   string
	entry audit.Event
}

// Ingress validates and queues extension outputs. It deliberately has no
// network listener and cannot mutate ACL or policy state.
type Ingress struct {
	mu           sync.Mutex
	sendMu       sync.Mutex
	queue        chan queuedOutput
	done         chan struct{}
	worker       sync.WaitGroup
	closed       bool
	idle         chan struct{}
	pending      int
	failures     int
	lastErr      error
	seen         map[string]ingressEntry
	seenCap      int
	seenTTL      time.Duration
	workerCtx    context.Context
	workerCancel context.CancelFunc
	keys         map[string]TrustKey
	pluginID     string
	version      string
	tenant       string
	site         string
	epoch        uint64
	maxTTL       time.Duration
	skew         time.Duration
	stream       string
	now          func() time.Time
	sink         OutputSink
	lastSeq      uint64
	hasSeq       bool
}

func NewIngress(options IngressOptions) (*Ingress, error) {
	if !validID(options.PluginID) || !validID(options.PluginVersion) || !validID(options.TenantRef) || !validID(options.SiteRef) || options.PolicyEpoch == 0 || !validID(options.StreamID) || options.Sink == nil || len(options.Keys) == 0 {
		return nil, ErrIngressConfig
	}
	if options.QueueCapacity == 0 {
		options.QueueCapacity = DefaultIngressQueueSize
	}
	if options.QueueCapacity < 0 || options.QueueCapacity > MaxIngressQueueSize {
		return nil, ErrIngressConfig
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	keys := make(map[string]TrustKey, len(options.Keys))
	for id, key := range options.Keys {
		if id == "" || key.ID != id || len(key.PublicKey) != ed25519.PublicKeySize {
			return nil, ErrIngressConfig
		}
		key.PublicKey = append(ed25519.PublicKey(nil), key.PublicKey...)
		keys[id] = key
	}
	seenCap := options.QueueCapacity * 8
	if seenCap < minSeenCapacity {
		seenCap = minSeenCapacity
	}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	ingress := &Ingress{
		queue: make(chan queuedOutput, options.QueueCapacity), done: make(chan struct{}), idle: closedIngressChan(), seen: make(map[string]ingressEntry),
		seenCap: seenCap, seenTTL: defaultSeenRetention, workerCtx: workerCtx, workerCancel: workerCancel,
		keys: keys, pluginID: options.PluginID, version: options.PluginVersion, tenant: options.TenantRef, site: options.SiteRef,
		epoch: options.PolicyEpoch, maxTTL: maxTTL(options.MaxTTL), skew: options.ClockSkew, stream: options.StreamID, now: options.Now, sink: options.Sink,
	}
	ingress.worker.Add(1)
	go ingress.run()
	return ingress, nil
}

func closedIngressChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Submit parses and verifies one complete wire message, then admits only its
// metadata to the bounded audit queue. The original payload is never retained.
func (i *Ingress) Submit(ctx context.Context, wire []byte) (Receipt, error) {
	if i == nil {
		return Receipt{}, ErrIngressClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	parsed, err := Parse(wire)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %s", ErrOutputRejected, AuditCode(err))
	}
	claims, err := decodeOutputClaims(parsed.Payload)
	if err != nil {
		return Receipt{}, err
	}
	now := i.now().UTC().Round(0)
	if err := Verify(parsed, i.keys, VerifyOptions{Now: now, MaxTTL: i.maxTTL, ClockSkew: i.skew, PolicyEpoch: i.epoch, TenantRef: i.tenant, SiteRef: i.site}); err != nil {
		return Receipt{}, fmt.Errorf("%w: %s", ErrOutputRejected, AuditCode(err))
	}
	if claims.PluginID != i.pluginID || claims.PluginVersion != i.version {
		return Receipt{}, ErrOutputRejected
	}
	key := claims.EventID + "\x00" + strconv.FormatUint(claims.Sequence, 10)
	digest := parsed.Integrity.PayloadSHA256
	auditEvent := audit.Event{
		EventID: eventID(i.pluginID, claims.EventID, claims.Sequence), StreamID: i.stream, TenantID: claims.TenantRef,
		Actor: claims.PluginID, Type: audit.EventTypeAudit, Action: "extension.output.accepted", Resource: "plugin:" + claims.PluginID,
		Outcome: audit.OutcomeSuccess, CorrelationID: claims.EventID, Reason: claims.APIVersion, EvidenceDigest: digest,
		PolicyEpoch: claims.PolicyEpoch, Class: audit.EventClassNormal, At: claims.ObservedAt.UTC().Round(0),
	}

	i.sendMu.Lock()
	defer i.sendMu.Unlock()
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return Receipt{}, ErrIngressClosed
	}
	i.pruneLocked(now)
	isNew := false
	if prior, ok := i.seen[key]; ok {
		if prior.digest != digest {
			i.mu.Unlock()
			return Receipt{}, ErrIngressReplay
		}
		if prior.pending || !prior.failed {
			i.mu.Unlock()
			return Receipt{EventID: claims.EventID, Sequence: claims.Sequence, PluginID: claims.PluginID, PluginVersion: claims.PluginVersion, PayloadDigest: digest, Duplicate: true}, nil
		}
		// Keep failed set until the retry actually succeeds; a queue-full
		// rejection must not make the entry look completed.
		prior.pending = true
		i.seen[key] = prior
		i.beginPendingLocked()
		i.mu.Unlock()
	} else {
		if i.hasSeq {
			switch {
			case claims.Sequence <= i.lastSeq:
				i.mu.Unlock()
				return Receipt{}, ErrIngressSequenceOld
			case claims.Sequence-i.lastSeq != 1:
				i.mu.Unlock()
				return Receipt{}, ErrIngressSequenceGap
			}
		}
		isNew = true
		i.seen[key] = ingressEntry{digest: digest, event: auditEvent, at: now, pending: true}
		i.beginPendingLocked()
		i.mu.Unlock()
	}
	select {
	case i.queue <- queuedOutput{key: key, entry: auditEvent}:
		if isNew {
			i.mu.Lock()
			i.lastSeq, i.hasSeq = claims.Sequence, true
			i.mu.Unlock()
		}
		return Receipt{EventID: claims.EventID, Sequence: claims.Sequence, PluginID: claims.PluginID, PluginVersion: claims.PluginVersion, PayloadDigest: digest}, nil
	default:
		i.mu.Lock()
		if isNew {
			// A rejected first admission must not leave a phantom receipt;
			// otherwise the retry would be answered as a duplicate.
			delete(i.seen, key)
		} else if prior, ok := i.seen[key]; ok {
			prior.pending = false
			i.seen[key] = prior
		}
		i.endPendingLocked()
		i.mu.Unlock()
		return Receipt{}, ErrIngressQueueFull
	}
}

func (i *Ingress) beginPendingLocked() {
	if i.pending == 0 {
		i.idle = make(chan struct{})
	}
	i.pending++
}

func (i *Ingress) endPendingLocked() {
	i.pending--
	if i.pending == 0 {
		close(i.idle)
	}
}

func (i *Ingress) run() {
	defer i.worker.Done()
	for item := range i.queue {
		ctx, cancel := context.WithTimeout(i.workerCtx, ingressAppendTimeout)
		_, err := i.sink.Append(ctx, item.entry)
		cancel()
		i.mu.Lock()
		prior := i.seen[item.key]
		prior.pending = false
		if err != nil {
			if !prior.failed {
				i.failures++
			}
			prior.failed = true
			i.lastErr = fmt.Errorf("%w: %v", ErrIngressAuditFailed, err)
		} else {
			if prior.failed {
				i.failures--
			}
			prior.failed = false
			prior.at = i.now().UTC()
			if i.failures == 0 {
				i.lastErr = nil
			}
		}
		i.seen[item.key] = prior
		i.endPendingLocked()
		i.pruneLocked(i.now().UTC())
		i.mu.Unlock()
	}
	close(i.done)
}

func (i *Ingress) Flush(ctx context.Context) error {
	if i == nil {
		return ErrIngressClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.mu.Lock()
	idle := i.idle
	i.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
		return ctx.Err()
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pruneLocked(i.now().UTC())
	if i.failures == 0 {
		return nil
	}
	if i.lastErr == nil {
		return ErrIngressAuditFailed
	}
	return i.lastErr
}

func (i *Ingress) Close() error {
	if i == nil {
		return nil
	}
	i.sendMu.Lock()
	i.mu.Lock()
	if !i.closed {
		i.closed = true
		close(i.queue)
	}
	i.mu.Unlock()
	i.sendMu.Unlock()
	i.workerCancel()
	waited := make(chan struct{})
	go func() {
		i.worker.Wait()
		close(waited)
	}()
	select {
	case <-waited:
		return nil
	case <-time.After(ingressCloseTimeout):
		return ErrIngressCloseTimeout
	}
}

// pruneLocked keeps the replay map bounded: successes expire after seenTTL and
// the oldest successes are dropped once seenCap is exceeded. Pending and failed
// entries are never dropped, so retries and Flush reporting stay correct.
func (i *Ingress) pruneLocked(now time.Time) {
	for key, entry := range i.seen {
		if entry.pending || entry.failed {
			continue
		}
		if now.Sub(entry.at) > i.seenTTL {
			delete(i.seen, key)
		}
	}
	if len(i.seen) <= i.seenCap {
		return
	}
	type agedEntry struct {
		key string
		at  time.Time
	}
	done := make([]agedEntry, 0, len(i.seen))
	for key, entry := range i.seen {
		if !entry.pending && !entry.failed {
			done = append(done, agedEntry{key: key, at: entry.at})
		}
	}
	sort.Slice(done, func(a, b int) bool { return done[a].at.Before(done[b].at) })
	for _, item := range done {
		if len(i.seen) <= i.seenCap {
			break
		}
		delete(i.seen, item.key)
	}
}

func eventID(pluginID, eventID string, sequence uint64) string {
	sum := sha256.Sum256([]byte(pluginID + "\x00" + eventID + "\x00" + strconv.FormatUint(sequence, 10)))
	return "ext:" + hex.EncodeToString(sum[:])
}
