// Package integration composes the diagnostics admission broker, encrypted
// envelope, durable queue, and metadata-only audit runtime into one lifecycle.
// Submit performs validation, sealing, and durable enqueueing. External upload
// adapters are invoked only by the queue worker.
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/envelope"
	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics/queue"
	"github.com/google/uuid"
)

var (
	ErrInvalidConfig    = errors.New("invalid diagnostics integration configuration")
	ErrUploaderRequired = errors.New("diagnostics integration requires an upload adapter")
	ErrProviderRequired = errors.New("diagnostics integration requires an envelope provider")
	ErrClosed           = errors.New("diagnostics integration is closed")
)

// UploadAdapter is the only external side-effect boundary. Implementations
// receive an encoded ciphertext envelope and metadata; plaintext is never
// exposed by this contract.
type UploadAdapter interface {
	Upload(context.Context, UploadRequest) error
}

// UploadFunc adapts a function to UploadAdapter for small integrations and
// tests without requiring a concrete client type.
type UploadFunc func(context.Context, UploadRequest) error

func (f UploadFunc) Upload(ctx context.Context, req UploadRequest) error {
	if f == nil {
		return ErrUploaderRequired
	}
	return f(ctx, req)
}

// ExternalUploader and ObjectUploader are compatibility spellings for callers
// that want the dependency to read like its deployment role.
type ExternalUploader = UploadAdapter
type ObjectUploader = UploadAdapter
type Options = Config

// UploadRequest is passed to the injected adapter from a queue worker.
type UploadRequest struct {
	UploadID      string
	TenantID      string
	PluginID      string
	PluginVersion string
	Target        string
	LeaseID       string
	PolicyEpoch   uint64
	Digest        string
	Attempt       int
	Envelope      []byte
}

// Config controls the composed runtime. QueueRoot is used only when Queue is
// nil; callers may inject an already opened queue for tests or another store.
type Config struct {
	QueueRoot   string
	QueueConfig queue.Config
	Queue       *queue.Store

	Broker       *diagnostics.Broker
	BrokerConfig diagnostics.Config

	Provider   envelope.KeyProvider
	KeyVersion string
	TenantID   string
	Actor      string
	StreamID   string

	Uploader     UploadAdapter
	ReplayGuard  envelope.ReplayGuard
	WorkerID     string
	PollInterval time.Duration
	AutoStart    bool

	Audit *audit.Runtime
}

// Receipt is the immediate admission result. UploadID is available before
// any external adapter is called.
type Receipt struct {
	UploadID      string
	State         diagnostics.State
	ExpiresAt     time.Time
	SchemaVersion string
	Digest        string
	ObjectDigest  string
}

// Status exposes queue metadata and encrypted bytes are intentionally absent.
type Status = queue.Item

// Runtime owns the composed queue worker and its injected dependencies.
type Runtime struct {
	mu       sync.Mutex
	admitMu  sync.Mutex
	broker   *diagnostics.Broker
	queue    *queue.Store
	provider envelope.KeyProvider
	keyVer   string
	tenant   string
	actor    string
	stream   string
	uploader UploadAdapter
	replay   envelope.ReplayGuard
	audit    *audit.Runtime
	poll     time.Duration
	ownedQ   bool
	closed   bool
	started  bool
}

func NewRuntime(cfg Config) (*Runtime, error) {
	if cfg.Provider == nil {
		return nil, ErrProviderRequired
	}
	if cfg.Uploader == nil {
		return nil, ErrUploaderRequired
	}
	if strings.TrimSpace(cfg.KeyVersion) == "" || strings.TrimSpace(cfg.TenantID) == "" || strings.TrimSpace(cfg.Actor) == "" {
		return nil, fmt.Errorf("%w: key version, tenant, and actor are required", ErrInvalidConfig)
	}
	if cfg.StreamID == "" {
		cfg.StreamID = "diagnostics"
	}
	if cfg.WorkerID == "" {
		cfg.WorkerID = "diagnostics-worker"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 100 * time.Millisecond
	}
	broker := cfg.Broker
	if broker == nil {
		var err error
		broker, err = diagnostics.NewBroker(cfg.BrokerConfig)
		if err != nil {
			return nil, err
		}
	}
	q := cfg.Queue
	owned := false
	if q == nil {
		if strings.TrimSpace(cfg.QueueRoot) == "" {
			return nil, fmt.Errorf("%w: queue root is required", ErrInvalidConfig)
		}
		var err error
		q, err = queue.NewStore(cfg.QueueRoot, cfg.QueueConfig)
		if err != nil {
			return nil, err
		}
		owned = true
	}
	r := &Runtime{broker: broker, queue: q, provider: cfg.Provider, keyVer: cfg.KeyVersion, tenant: cfg.TenantID, actor: cfg.Actor, stream: cfg.StreamID, uploader: cfg.Uploader, replay: cfg.ReplayGuard, audit: cfg.Audit, poll: cfg.PollInterval, ownedQ: owned}
	if cfg.AutoStart {
		if err := r.Start(context.Background()); err != nil {
			if owned {
				_ = q.Close()
			}
			return nil, err
		}
	}
	return r, nil
}

func New(cfg Config) (*Runtime, error)  { return NewRuntime(cfg) }
func Open(cfg Config) (*Runtime, error) { return NewRuntime(cfg) }

// Submit validates through the existing broker, seals the fixed diagnostic
// package, and durably enqueues the encoded envelope before returning.
func (r *Runtime) Submit(ctx context.Context, req diagnostics.Request) (Receipt, error) {
	if r == nil {
		return Receipt{}, ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if !strictIdentifier(req.Target) || !strictIdentifier(req.PluginID) || !strictIdentifier(req.PluginVersion) || !strictIdentifier(req.LeaseID) || !strictIdentifier(req.IdempotencyKey) {
		return Receipt{}, diagnostics.ErrInvalidRequest
	}
	r.admitMu.Lock()
	defer r.admitMu.Unlock()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Receipt{}, ErrClosed
	}
	reserved, err := r.broker.Submit(ctx, req)
	r.mu.Unlock()
	if err != nil {
		return Receipt{}, err
	}
	rootID := reserved.UploadID
	brokerOwned := reserved.State == diagnostics.StateQueued
	defer func() {
		if !brokerOwned {
			return
		}
		if item, ok := r.broker.Next(); ok && item.UploadID == rootID {
			_ = r.broker.Complete(rootID, true)
		}
	}()
	if existing, found, conflict := r.findExisting(ctx, req, payloadDigest(req.Package)); found {
		if conflict {
			return Receipt{}, diagnostics.ErrIdempotencyConflict
		}
		return receiptFromQueue(existing), nil
	}
	if existing, statusErr := r.queue.Status(ctx, reserved.UploadID); statusErr == nil {
		if existing.IdempotencyKey == req.IdempotencyKey {
			return receiptFromQueue(existing), nil
		}
		// A freshly started in-memory broker can reuse an upload-N identifier
		// that is already present on disk. Let the durable queue allocate the
		// next identifier instead of colliding with the recovered record.
		reserved.UploadID = ""
	} else if errors.Is(statusErr, queue.ErrExpired) {
		return Receipt{}, diagnostics.ErrExpired
	}

	payload, err := json.Marshal(req.Package)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: encode package", diagnostics.ErrInvalidRequest)
	}
	defer wipe(payload)
	env, err := envelope.Seal(ctx, payload, envelope.Metadata{TenantID: r.tenant, PluginID: req.PluginID, PluginVersion: req.PluginVersion, Target: req.Target, PolicyEpoch: req.PolicyEpoch}, r.keyVer, r.provider)
	if err != nil {
		return Receipt{}, err
	}
	encoded, err := envelope.Encode(env)
	if err != nil {
		return Receipt{}, err
	}
	defer wipe(encoded)
	queueReq := queue.Request{TenantID: r.tenant, PluginID: req.PluginID, PluginVersion: req.PluginVersion, Target: req.Target, LeaseID: req.LeaseID, IdempotencyKey: req.IdempotencyKey, PolicyEpoch: req.PolicyEpoch, ExpiresAt: reserved.ExpiresAt}
	if reserved.UploadID != "" {
		queueReq.ID, queueReq.UploadID = reserved.UploadID, reserved.UploadID
	} else {
		freshID := "upload-" + uuid.NewString()
		queueReq.ID, queueReq.UploadID = freshID, freshID
	}
	qr, err := r.queue.EnqueueEncrypted(ctx, queueReq, encoded)
	if err != nil {
		return Receipt{}, err
	}
	// Keep the in-memory broker's matching item from retaining the package in
	// its queue. The durable queue is authoritative after this point.
	if item, ok := r.broker.Next(); !ok || item.UploadID != rootID {
		return Receipt{}, fmt.Errorf("%w: broker admission mismatch", ErrInvalidConfig)
	}
	if err := r.broker.Complete(rootID, true); err != nil {
		return Receipt{}, err
	}
	brokerOwned = false
	r.auditSubmit(ctx, queue.Item{UploadID: qr.UploadID, LeaseID: req.LeaseID, PolicyEpoch: req.PolicyEpoch, ObjectDigest: qr.ObjectDigest})
	return receiptFromQueue(queue.Item{UploadID: qr.UploadID, State: qr.State, ExpiresAt: qr.ExpiresAt, ObjectDigest: qr.ObjectDigest}), nil
}

func (r *Runtime) Start(ctx context.Context) error {
	if r == nil {
		return ErrClosed
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.started = true
	r.mu.Unlock()
	if err := r.queue.Start(ctx, r.handle); err != nil {
		r.mu.Lock()
		r.started = false
		r.mu.Unlock()
		return err
	}
	return nil
}

func (r *Runtime) handle(ctx context.Context, item queue.Item) error {
	defer func() {
		wipe(item.Ciphertext)
		wipe(item.Envelope)
		wipe(item.Payload)
		wipe(item.EncryptedPayload)
	}()
	decoded, err := envelope.Decode(item.Ciphertext)
	if err != nil {
		r.auditEvent(ctx, item, "validate", audit.OutcomeFailure, err)
		return err
	}
	if err := envelope.Verify(ctx, decoded, r.provider); err != nil {
		r.auditEvent(ctx, item, "validate", audit.OutcomeFailure, err)
		return err
	}
	if decoded.Metadata.TenantID != item.TenantID || decoded.Metadata.PluginID != item.PluginID || decoded.Metadata.PluginVersion != item.PluginVersion || decoded.Metadata.Target != item.Target || decoded.Metadata.PolicyEpoch != item.PolicyEpoch {
		err := envelope.ErrInvalidMetadata
		r.auditEvent(ctx, item, "validate", audit.OutcomeFailure, err)
		return err
	}
	r.auditEvent(ctx, item, "started", audit.OutcomeStarted, nil)
	var replayID string
	var transactional envelope.TransactionalReplayGuard
	reserved := false
	if r.replay != nil {
		replayID = decoded.ID
		if replayID == "" {
			replayID = decoded.EnvelopeID
		}
		if candidate, ok := r.replay.(envelope.TransactionalReplayGuard); ok {
			transactional = candidate
			if err := transactional.Reserve(ctx, replayID); err != nil {
				r.auditEvent(ctx, item, "replay", audit.OutcomeDenied, err)
				return err
			}
			reserved = true
		}
	}
	err = r.uploader.Upload(ctx, UploadRequest{UploadID: item.UploadID, TenantID: item.TenantID, PluginID: item.PluginID, PluginVersion: item.PluginVersion, Target: item.Target, LeaseID: item.LeaseID, PolicyEpoch: item.PolicyEpoch, Digest: item.ObjectDigest, Attempt: item.Attempt, Envelope: cloneBytes(item.Ciphertext)})
	if err != nil {
		if reserved {
			if releaseErr := transactional.Release(context.WithoutCancel(ctx), replayID); releaseErr != nil {
				err = errors.Join(err, releaseErr)
			}
		}
		r.auditEvent(ctx, item, "failed", audit.OutcomeFailure, err)
		return err
	}
	if r.replay != nil {
		if reserved {
			// A successful external side effect is terminal for the queue item;
			// commit with a non-cancelable context so caller cancellation cannot
			// turn a successful upload into a duplicate retry.
			if commitErr := transactional.Commit(context.WithoutCancel(ctx), replayID); commitErr != nil {
				// Do not return an error here: the external upload already
				// succeeded, and returning one would make the queue retry the same
				// side effect. Preserve the uncertainty as an audit event so an
				// operator can reconcile the replay barrier explicitly.
				r.auditEvent(ctx, item, "replay_commit", audit.OutcomeFailure, commitErr)
			}
		} else {
			// Legacy guards cannot exclude concurrent uploaders. Their adapter
			// must therefore be idempotent by UploadID or object digest.
			if markErr := r.replay.CheckAndMark(context.WithoutCancel(ctx), replayID); markErr != nil {
				// The upload is already complete; surface a legacy guard failure
				// for reconciliation without asking the queue to duplicate it.
				r.auditEvent(ctx, item, "replay_commit", audit.OutcomeFailure, markErr)
			}
		}
	}
	r.auditEvent(ctx, item, "completed", audit.OutcomeSuccess, nil)
	return nil
}

func (r *Runtime) auditEvent(ctx context.Context, item queue.Item, action string, outcome audit.Outcome, cause error) {
	if r.audit == nil {
		return
	}
	reason := ""
	if cause != nil {
		reason = reasonCode(cause)
	}
	e := audit.Event{EventID: fmt.Sprintf("diagnostic-%s-%s-%d", action, item.UploadID, item.Attempt), StreamID: r.stream, TenantID: r.tenant, Actor: r.actor, Type: audit.EventTypeUpload, Action: action, Resource: "diagnostic/" + item.UploadID, Outcome: outcome, LeaseID: item.LeaseID, Reason: reason, EvidenceDigest: item.ObjectDigest, PolicyEpoch: item.PolicyEpoch, Class: audit.EventClassNormal, At: time.Now().UTC()}
	_, _ = r.audit.Append(ctx, e)
}

func (r *Runtime) auditSubmit(ctx context.Context, item queue.Item) {
	if r.audit == nil {
		return
	}
	e := audit.Event{EventID: "diagnostic-submitted-" + item.UploadID, StreamID: r.stream, TenantID: r.tenant, Actor: r.actor, Type: audit.EventTypeUpload, Action: "submitted", Resource: "diagnostic/" + item.UploadID, Outcome: audit.OutcomeStarted, LeaseID: item.LeaseID, EvidenceDigest: item.ObjectDigest, PolicyEpoch: item.PolicyEpoch, Class: audit.EventClassNormal, At: time.Now().UTC()}
	_, _ = r.audit.Append(ctx, e)
}

func (r *Runtime) findExisting(ctx context.Context, req diagnostics.Request, digest string) (queue.Item, bool, bool) {
	items, err := r.queue.Snapshot(ctx)
	if err != nil {
		return queue.Item{}, false, false
	}
	for _, item := range items {
		if item.IdempotencyKey != req.IdempotencyKey {
			continue
		}
		if item.TenantID != r.tenant || item.PluginID != req.PluginID || item.PluginVersion != req.PluginVersion || item.Target != req.Target || item.LeaseID != req.LeaseID || item.PolicyEpoch != req.PolicyEpoch {
			return item, true, true
		}
		raw, readErr := r.queue.ReadEnvelope(ctx, item.ID)
		if readErr == nil {
			env, decodeErr := envelope.Decode(raw)
			wipe(raw)
			if decodeErr == nil && env.Metadata.SHA256Digest != digest {
				return item, true, true
			}
		}
		return item, true, false
	}
	return queue.Item{}, false, false
}

func payloadDigest(pkg diagnostics.Package) string {
	b, _ := json.Marshal(pkg)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func reasonCode(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, envelope.ErrAuthentication) || errors.Is(err, envelope.ErrDigestMismatch) {
		return "envelope.invalid"
	}
	if errors.Is(err, queue.ErrCorrupt) {
		return "queue.corrupt"
	}
	return "upload.failed"
}

func (r *Runtime) Wait(ctx context.Context) error {
	if r == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(r.poll)
	defer ticker.Stop()
	for {
		stats := r.queue.Stats()
		if stats.LastError != nil {
			return stats.LastError
		}
		if stats.Pending == 0 {
			if r.audit != nil {
				if err := r.audit.Flush(ctx); err != nil {
					return err
				}
				if err := r.audit.Dispatch(ctx, 0); err != nil {
					return err
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Runtime) Status(ctx context.Context, id string) (Status, error) {
	if r == nil {
		return Status{}, ErrClosed
	}
	return r.queue.Status(ctx, id)
}

func (r *Runtime) Retry(ctx context.Context, id string) error {
	if r == nil {
		return ErrClosed
	}
	return r.queue.Retry(ctx, id)
}

func (r *Runtime) Pause(ctx context.Context) error {
	if r == nil {
		return ErrClosed
	}
	return r.queue.Pause(ctx)
}

func (r *Runtime) Resume(ctx context.Context) error {
	if r == nil {
		return ErrClosed
	}
	return r.queue.Resume(ctx)
}

func (r *Runtime) ReplayAudit(ctx context.Context) error {
	if r == nil || r.audit == nil {
		return nil
	}
	return r.audit.Replay(ctx)
}

func (r *Runtime) DispatchAudit(ctx context.Context, limit int) error {
	if r == nil || r.audit == nil {
		return nil
	}
	return r.audit.Dispatch(ctx, limit)
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()
	if r.queue != nil && r.ownedQ {
		_ = r.queue.Close()
	}
	return nil
}

func (r *Runtime) Stop() error {
	if r == nil || r.queue == nil {
		return nil
	}
	err := r.queue.Stop()
	r.mu.Lock()
	r.started = false
	r.mu.Unlock()
	return err
}

func (r *Runtime) Queue() *queue.Store {
	if r == nil {
		return nil
	}
	return r.queue
}
func (r *Runtime) Audit() *audit.Runtime {
	if r == nil {
		return nil
	}
	return r.audit
}

func cloneUploadRequest(in UploadRequest) UploadRequest {
	in.Envelope = cloneBytes(in.Envelope)
	return in
}

func receiptFromQueue(item queue.Item) Receipt {
	return Receipt{UploadID: item.UploadID, State: diagnostics.State(item.State), ExpiresAt: item.ExpiresAt, SchemaVersion: diagnostics.SchemaVersion, Digest: item.ObjectDigest, ObjectDigest: item.ObjectDigest}
}

func strictIdentifier(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func cloneBytes(in []byte) []byte { return append([]byte(nil), in...) }

func wipe(in []byte) {
	for i := range in {
		in[i] = 0
	}
}
