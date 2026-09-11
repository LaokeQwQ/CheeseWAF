package audit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

type RuntimeOptions struct {
	Journal         Journal
	Spool           EncryptedSpool
	Signer          Signer
	Verifiers       map[string]ed25519.PublicKey
	Outboxes        []OutboxAdapter
	StreamID        string
	QueueCapacity   int
	CheckpointEvery uint64
	Now             func() time.Time
}

type queuedEvent struct {
	event  Event
	result chan appendResult
}
type appendResult struct {
	record Record
	err    error
}
type Runtime struct {
	journal         Journal
	spool           EncryptedSpool
	signer          Signer
	verifiers       map[string]ed25519.PublicKey
	outboxes        []OutboxAdapter
	stream          string
	checkpointEvery uint64
	now             func() time.Time
	queue           chan queuedEvent
	worker          sync.WaitGroup
	appendMu        sync.Mutex
	mu              sync.Mutex
	pending         int
	idle            chan struct{}
	closed          bool
	firstErr        error
	head            Record
	events          map[string]Record
	spooling        bool
}

func NewRuntime(o RuntimeOptions) (*Runtime, error) {
	if o.Journal == nil {
		return nil, errors.New("audit journal is required")
	}
	if o.StreamID == "" {
		o.StreamID = "default"
	}
	if !validID(o.StreamID, false) {
		return nil, ErrInvalidEvent
	}
	if o.QueueCapacity <= 0 {
		o.QueueCapacity = 64
	}
	if o.QueueCapacity > 65536 {
		return nil, ErrQueueFull
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.CheckpointEvery > 0 && o.Signer == nil {
		return nil, ErrSignerUnavailable
	}
	r := &Runtime{journal: o.Journal, spool: o.Spool, signer: o.Signer, verifiers: cloneVerifierKeys(o.Verifiers), outboxes: append([]OutboxAdapter(nil), o.Outboxes...), stream: o.StreamID, checkpointEvery: o.CheckpointEvery, now: o.Now, queue: make(chan queuedEvent, o.QueueCapacity), idle: closedChan(), events: make(map[string]Record), spooling: !o.Journal.Durable() && o.Spool != nil}
	if s, ok := o.Signer.(Ed25519Signer); ok && len(r.verifiers) == 0 && len(s.PrivateKey) == ed25519.PrivateKeySize {
		r.verifiers = map[string]ed25519.PublicKey{s.ID: append(ed25519.PublicKey(nil), s.PrivateKey.Public().(ed25519.PublicKey)...)}
	}
	last, err := o.Journal.Last(context.Background(), o.StreamID)
	if err != nil {
		return nil, err
	}
	r.head = last
	rows, err := o.Journal.Records(context.Background(), o.StreamID, 0, 0)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		r.events[row.Event.EventID] = row
	}
	if err := o.Journal.Verify(context.Background(), o.StreamID); err != nil {
		return nil, err
	}
	for _, row := range rows {
		cp, err := o.Journal.Checkpoint(context.Background(), o.StreamID, row.Sequence)
		if err != nil {
			return nil, err
		}
		if cp == nil {
			continue
		}
		if len(r.verifiers) == 0 || VerifyCheckpoint(o.StreamID, row, *cp, r.verifiers) != nil {
			return nil, ErrCheckpointInvalid
		}
	}
	r.worker.Add(1)
	go r.run()
	return r, nil
}
func closedChan() chan struct{} { ch := make(chan struct{}); close(ch); return ch }
func cloneVerifierKeys(in map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(in))
	for id, key := range in {
		out[id] = append(ed25519.PublicKey(nil), key...)
	}
	return out
}

// Append persists critical events before returning. Normal events are accepted
// into a bounded queue and persisted by the worker.
func (r *Runtime) Append(ctx context.Context, event Event) (Record, error) {
	if r == nil {
		return Record{}, ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if event.StreamID == "" {
		event.StreamID = r.stream
	}
	if event.At.IsZero() {
		event.At = r.now().UTC()
	}
	if err := validateEvent(event); err != nil {
		return Record{}, err
	}
	if event.StreamID != r.stream {
		return Record{}, ErrInvalidEvent
	}
	if event.Class == EventClassCritical {
		if !r.journal.Durable() && (r.spool == nil || !r.spool.Durable()) {
			return Record{}, ErrNoDurableChannel
		}
		if err := r.waitIdle(ctx); err != nil {
			return Record{}, err
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return Record{}, ErrClosed
		}
		r.beginPendingLocked()
		r.mu.Unlock()
		record, err := r.persist(ctx, event)
		r.endPending()
		return record, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Record{}, ErrClosed
	}
	r.beginPendingLocked()
	select {
	case r.queue <- queuedEvent{event: event}:
		return Record{}, nil
	case <-ctx.Done():
		r.endPendingLocked()
		return Record{}, ctx.Err()
	default:
		r.endPendingLocked()
		return Record{}, ErrQueueFull
	}
}
func (r *Runtime) AppendEvent(ctx context.Context, event Event) (Record, error) {
	return r.Append(ctx, event)
}
func (r *Runtime) beginPendingLocked() {
	if r.pending == 0 {
		r.idle = make(chan struct{})
	}
	r.pending++
}
func (r *Runtime) endPending() { r.mu.Lock(); r.endPendingLocked(); r.mu.Unlock() }
func (r *Runtime) endPendingLocked() {
	r.pending--
	if r.pending == 0 {
		close(r.idle)
	}
}

func (r *Runtime) persist(ctx context.Context, event Event) (Record, error) {
	r.appendMu.Lock()
	defer r.appendMu.Unlock()
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	if prior, ok := r.events[event.EventID]; ok {
		if eventEqual(prior.Event, event) {
			return prior, nil
		}
		return Record{}, ErrReplayConflict
	}
	for attempt := 0; attempt < 8; attempt++ {
		sequence := r.head.Sequence + 1
		if sequence == 0 {
			sequence = 1
		}
		previous := r.head.Hash
		rec := Record{Sequence: sequence, Event: event, PreviousHash: previous}
		rec.Hash = hashRecord(rec)
		cp, err := r.makeCheckpoint(event, rec)
		if err != nil {
			return Record{}, err
		}
		if cp != nil && len(r.verifiers) > 0 {
			if VerifyCheckpoint(r.stream, rec, *cp, r.verifiers) != nil {
				return Record{}, ErrCheckpointInvalid
			}
		}
		outbox := make([]Delivery, 0, len(r.outboxes))
		for _, adapter := range r.outboxes {
			if adapter != nil {
				outbox = append(outbox, Delivery{DeliveryID: deliveryID(r.stream, rec.Sequence, adapter.Target()), Target: adapter.Target(), StreamID: r.stream, Sequence: rec.Sequence, EventID: event.EventID, RecordHash: rec.Hash, CreatedAt: r.now().UTC()})
			}
		}
		commit := Commit{Record: rec, Checkpoint: cp, Outbox: outbox}
		if r.spooling {
			if r.spool == nil || !r.spool.Durable() && event.Class == EventClassCritical {
				return Record{}, ErrNoDurableChannel
			}
			if err := r.spool.Put(ctx, commit); err != nil {
				return Record{}, err
			}
			r.head = rec
			r.events[event.EventID] = rec
			return rec, nil
		}
		err = r.journal.Append(ctx, commit)
		if err == nil {
			r.head = rec
			r.events[event.EventID] = rec
			return rec, nil
		}
		if errors.Is(err, ErrSequenceConflict) {
			last, e := r.journal.Last(ctx, r.stream)
			if e != nil {
				return Record{}, e
			}
			r.head = last
			continue
		}
		if errors.Is(err, ErrUnavailable) && r.spool != nil && r.spool.Durable() {
			r.spooling = true
			continue
		}
		return Record{}, err
	}
	return Record{}, ErrSequenceConflict
}
func (r *Runtime) makeCheckpoint(event Event, rec Record) (*Checkpoint, error) {
	if r.signer == nil || !(event.Class == EventClassCritical || r.checkpointEvery > 0 && rec.Sequence%r.checkpointEvery == 0) {
		return nil, nil
	}
	cp := Checkpoint{StreamID: r.stream, Sequence: rec.Sequence, Hash: rec.Hash, KeyID: r.signer.KeyID(), At: r.now().UTC()}
	sig, err := r.signer.Sign(checkpointMessage(cp))
	if err != nil {
		return nil, err
	}
	cp.Signature = append([]byte(nil), sig...)
	return &cp, nil
}
func deliveryID(stream string, sequence uint64, target OutboxTarget) string {
	return fmt.Sprintf("%s/%d/%s", stream, sequence, target)
}

func (r *Runtime) run() {
	defer r.worker.Done()
	for item := range r.queue {
		record, err := r.persist(context.Background(), item.event)
		if err != nil {
			r.mu.Lock()
			if r.firstErr == nil {
				r.firstErr = err
			}
			r.mu.Unlock()
		}
		if item.result != nil {
			item.result <- appendResult{record: record, err: err}
		}
		r.endPending()
	}
}
func (r *Runtime) Flush(ctx context.Context) error {
	if r == nil {
		return ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := r.waitIdle(ctx); err != nil {
		return err
	}
	if err := r.journal.Flush(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.firstErr
}

func (r *Runtime) waitIdle(ctx context.Context) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	idle := r.idle
	r.mu.Unlock()
	select {
	case <-idle:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Replay decrypts and verifies local spool commits. A recovered durable journal
// is the only condition under which the spool may acknowledge an entry.
func (r *Runtime) Replay(ctx context.Context) error {
	if r == nil || r.spool == nil {
		return nil
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	r.appendMu.Lock()
	defer r.appendMu.Unlock()
	entries, err := r.spool.Entries(ctx, r.stream)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		commit, err := r.spool.Open(ctx, entry)
		if err != nil {
			return err
		}
		if err := validateCommit(commit); err != nil {
			return ErrSpoolCorrupt
		}
		if err := r.journal.Append(ctx, commit); err != nil && !errors.Is(err, ErrReplayConflict) {
			return err
		}
		if commit.Record.Sequence > r.head.Sequence {
			r.head = commit.Record
			r.events[commit.Record.Event.EventID] = commit.Record
		}
		if r.journal.Durable() {
			if err := r.spool.Ack(ctx, entry); err != nil {
				return err
			}
		}
	}
	r.spooling = !r.journal.Durable()
	return nil
}

// Dispatch drains metadata-only outbox rows. A delivery failure leaves the
// row pending so a later call can retry without changing the audit chain.
func (r *Runtime) Dispatch(ctx context.Context, limit int) error {
	if r == nil {
		return ErrInvalidRecord
	}
	pending, err := r.journal.PendingOutbox(ctx, r.stream, limit)
	if err != nil {
		return err
	}
	for _, d := range pending {
		var adapter OutboxAdapter
		for _, candidate := range r.outboxes {
			if candidate != nil && candidate.Target() == d.Target {
				adapter = candidate
				break
			}
		}
		if adapter == nil {
			continue
		}
		if err := adapter.Deliver(ctx, d); err != nil {
			return err
		}
		if err := r.journal.AckOutbox(ctx, d); err != nil {
			return err
		}
	}
	return nil
}

// Verify checks the chain and every stored checkpoint against the configured
// verification keys. A chain containing a checkpoint cannot be considered
// verified when its public key is absent.
func (r *Runtime) Verify(ctx context.Context) error {
	if r == nil {
		return ErrInvalidRecord
	}
	if err := r.journal.Verify(ctx, r.stream); err != nil {
		return err
	}
	rows, err := r.journal.Records(ctx, r.stream, 0, 0)
	if err != nil {
		return err
	}
	for _, row := range rows {
		cp, err := r.journal.Checkpoint(ctx, r.stream, row.Sequence)
		if err != nil {
			return err
		}
		if cp == nil {
			continue
		}
		if len(r.verifiers) == 0 || VerifyCheckpoint(r.stream, row, *cp, r.verifiers) != nil {
			return ErrCheckpointInvalid
		}
	}
	return nil
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
	close(r.queue)
	r.mu.Unlock()
	r.worker.Wait()
	return r.Flush(context.Background())
}
