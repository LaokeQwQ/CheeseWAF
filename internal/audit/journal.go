package audit

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Journal is the narrow persistence contract for an append-only stream. Append
// must atomically make the record, checkpoint, and outbox metadata visible.
type Journal interface {
	Append(context.Context, Commit) error
	Records(context.Context, string, uint64, int) ([]Record, error)
	Last(context.Context, string) (Record, error)
	Checkpoint(context.Context, string, uint64) (*Checkpoint, error)
	PendingOutbox(context.Context, string, int) ([]Delivery, error)
	AckOutbox(context.Context, Delivery) error
	Verify(context.Context, string) error
	Durable() bool
	Flush(context.Context) error
}

type memoryStream struct{ commits []Commit }
type MemoryJournal struct {
	mu      sync.RWMutex
	durable bool
	streams map[string]*memoryStream
	outbox  map[string]Delivery
}

// MemoryJournal is a deterministic test implementation. The optional
// durability flag exists only for contract tests; production must use a real
// append-only store and never infer durability from this type.
func NewMemoryJournal() *MemoryJournal { return NewMemoryJournalWithDurability(false) }
func NewMemoryJournalWithDurability(durable bool) *MemoryJournal {
	return &MemoryJournal{durable: durable, streams: make(map[string]*memoryStream), outbox: make(map[string]Delivery)}
}
func (j *MemoryJournal) Durable() bool                   { return j != nil && j.durable }
func (j *MemoryJournal) Flush(ctx context.Context) error { return contextErr(ctx) }

func (j *MemoryJournal) Append(ctx context.Context, commit Commit) error {
	if j == nil {
		return ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateCommit(commit); err != nil {
		return err
	}
	c := cloneCommit(commit)
	stream := c.Record.Event.StreamID
	j.mu.Lock()
	defer j.mu.Unlock()
	state := j.streams[stream]
	if state == nil {
		state = &memoryStream{}
		j.streams[stream] = state
	}
	rows := state.commits
	if c.Record.Sequence <= uint64(len(rows)) {
		prior := rows[c.Record.Sequence-1]
		if commitEqual(prior, c) {
			return nil
		}
		return ErrReplayConflict
	}
	if c.Record.Sequence != uint64(len(rows))+1 {
		return ErrSequenceConflict
	}
	if len(rows) > 0 && c.Record.PreviousHash != rows[len(rows)-1].Record.Hash {
		return ErrSequenceConflict
	}
	for _, prior := range rows {
		if prior.Record.Event.EventID == c.Record.Event.EventID {
			return ErrReplayConflict
		}
	}
	for _, d := range c.Outbox {
		if prior, ok := j.outbox[d.DeliveryID]; ok && !deliveryEqual(prior, d) {
			return ErrOutboxConflict
		}
	}
	state.commits = append(rows, c)
	for _, d := range c.Outbox {
		j.outbox[d.DeliveryID] = d
	}
	return nil
}

func (j *MemoryJournal) Records(ctx context.Context, stream string, after uint64, limit int) ([]Record, error) {
	if j == nil {
		return nil, ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	state := j.streams[stream]
	if state == nil {
		return nil, nil
	}
	if err := verifyCommits(state.commits); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = len(state.commits)
	}
	out := make([]Record, 0, limit)
	for _, c := range state.commits {
		if c.Record.Sequence > after {
			out = append(out, cloneRecord(c.Record))
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (j *MemoryJournal) Last(ctx context.Context, stream string) (Record, error) {
	if j == nil {
		return Record{}, ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	state := j.streams[stream]
	if state == nil || len(state.commits) == 0 {
		return Record{}, nil
	}
	if err := verifyCommits(state.commits); err != nil {
		return Record{}, err
	}
	return cloneRecord(state.commits[len(state.commits)-1].Record), nil
}
func (j *MemoryJournal) Checkpoint(ctx context.Context, stream string, sequence uint64) (*Checkpoint, error) {
	if j == nil {
		return nil, ErrCheckpointInvalid
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	state := j.streams[stream]
	if state == nil || sequence == 0 || sequence > uint64(len(state.commits)) {
		return nil, nil
	}
	cp := state.commits[sequence-1].Checkpoint
	if cp == nil {
		return nil, nil
	}
	out := *cp
	out.Signature = append([]byte(nil), cp.Signature...)
	return &out, nil
}
func (j *MemoryJournal) PendingOutbox(ctx context.Context, stream string, limit int) ([]Delivery, error) {
	if j == nil {
		return nil, ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	out := make([]Delivery, 0)
	for _, d := range j.outbox {
		if d.StreamID == stream && d.DeliveredAt.IsZero() {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].Sequence == out[k].Sequence {
			return out[i].Target < out[k].Target
		}
		return out[i].Sequence < out[k].Sequence
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (j *MemoryJournal) AckOutbox(ctx context.Context, d Delivery) error {
	if j == nil {
		return ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	prior, ok := j.outbox[d.DeliveryID]
	if !ok {
		return nil
	}
	if !deliveryIdentityEqual(prior, d) {
		return ErrOutboxConflict
	}
	prior.DeliveredAt = d.DeliveredAt
	if prior.DeliveredAt.IsZero() {
		prior.DeliveredAt = timeNowUTC()
	}
	j.outbox[d.DeliveryID] = prior
	return nil
}
func (j *MemoryJournal) Verify(ctx context.Context, stream string) error {
	if j == nil {
		return ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	state := j.streams[stream]
	if state == nil {
		return nil
	}
	return verifyCommits(state.commits)
}

func verifyCommits(commits []Commit) error {
	var previous string
	for i, c := range commits {
		if c.Record.Sequence != uint64(i+1) || c.Record.PreviousHash != previous || validateCommit(c) != nil {
			return ErrCorruptChain
		}
		previous = c.Record.Hash
	}
	return nil
}
func cloneRecord(r Record) Record { return r }
func cloneCommits(in []Commit) []Commit {
	out := make([]Commit, len(in))
	for i := range in {
		out[i] = cloneCommit(in[i])
	}
	return out
}
func deliveryEqual(a, b Delivery) bool { return a == b }
func deliveryIdentityEqual(a, b Delivery) bool {
	return a.DeliveryID == b.DeliveryID && a.Target == b.Target && a.StreamID == b.StreamID && a.Sequence == b.Sequence && a.EventID == b.EventID && a.RecordHash == b.RecordHash && a.CreatedAt.Equal(b.CreatedAt)
}
func timeNowUTC() time.Time { return time.Now().UTC() }

var _ Journal = (*MemoryJournal)(nil)
