package audit

import (
	"context"
	"sort"
	"sync"
	"time"
)

type OutboxTarget string

const (
	OutboxTargetPostgres OutboxTarget = "postgres"
	OutboxTargetWORM     OutboxTarget = "worm"
	OutboxTargetSIEM     OutboxTarget = "siem"
)

// Delivery is routing metadata only. The event itself is already in Journal;
// a destination receives the chain hash and stable identifiers, never payload.
type Delivery struct {
	DeliveryID  string       `json:"delivery_id"`
	Target      OutboxTarget `json:"target"`
	StreamID    string       `json:"stream_id"`
	Sequence    uint64       `json:"sequence"`
	EventID     string       `json:"event_id"`
	RecordHash  string       `json:"record_hash"`
	CreatedAt   time.Time    `json:"created_at"`
	DeliveredAt time.Time    `json:"delivered_at,omitempty"`
}

type OutboxAdapter interface {
	Target() OutboxTarget
	Deliver(context.Context, Delivery) error
	Durable() bool
}

// OutboxContract is the narrow queue contract used by PostgreSQL, WORM, and
// SIEM adapters. It stores metadata only and supports idempotent retries.
type OutboxContract interface {
	Enqueue(context.Context, Delivery) error
	Pending(context.Context, int) ([]Delivery, error)
	MarkDelivered(context.Context, Delivery) error
}

// Named contracts make the intended production bindings explicit while
// allowing PG/WORM/SIEM implementations to share the same narrow interface.
type PGOutboxAdapter interface {
	OutboxAdapter
	OutboxContract
}
type WORMOutboxAdapter interface {
	OutboxAdapter
	OutboxContract
}
type SIEMOutboxAdapter interface {
	OutboxAdapter
	OutboxContract
}

type MemoryOutboxAdapter struct {
	mu      sync.Mutex
	target  OutboxTarget
	items   map[string]Delivery
	durable bool
}

func NewMemoryOutboxAdapter(target OutboxTarget, durable ...bool) *MemoryOutboxAdapter {
	d := false
	if len(durable) > 0 {
		d = durable[0]
	}
	return &MemoryOutboxAdapter{target: target, durable: d, items: make(map[string]Delivery)}
}
func NewMemoryPGOutboxAdapter(durable ...bool) *MemoryOutboxAdapter {
	return NewMemoryOutboxAdapter(OutboxTargetPostgres, durable...)
}
func NewMemoryWORMOutboxAdapter(durable ...bool) *MemoryOutboxAdapter {
	return NewMemoryOutboxAdapter(OutboxTargetWORM, durable...)
}
func NewMemorySIEMOutboxAdapter(durable ...bool) *MemoryOutboxAdapter {
	return NewMemoryOutboxAdapter(OutboxTargetSIEM, durable...)
}
func (a *MemoryOutboxAdapter) Target() OutboxTarget {
	if a == nil {
		return ""
	}
	return a.target
}
func (a *MemoryOutboxAdapter) Durable() bool { return a != nil && a.durable }
func (a *MemoryOutboxAdapter) Deliver(ctx context.Context, d Delivery) error {
	if a == nil {
		return ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if validateDelivery(d) != nil || d.Target != a.target {
		return ErrOutboxInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if prior, ok := a.items[d.DeliveryID]; ok {
		if deliveryEqual(prior, d) {
			return nil
		}
		return ErrOutboxConflict
	}
	a.items[d.DeliveryID] = d
	return nil
}

func (a *MemoryOutboxAdapter) Enqueue(ctx context.Context, d Delivery) error {
	return a.Deliver(ctx, d)
}
func (a *MemoryOutboxAdapter) Pending(ctx context.Context, limit int) ([]Delivery, error) {
	if a == nil {
		return nil, ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Delivery, 0)
	for _, d := range a.items {
		if d.DeliveredAt.IsZero() {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].DeliveryID < out[k].DeliveryID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (a *MemoryOutboxAdapter) MarkDelivered(ctx context.Context, d Delivery) error {
	if a == nil {
		return ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if validateDelivery(d) != nil || d.Target != a.target {
		return ErrOutboxInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prior, ok := a.items[d.DeliveryID]
	if !ok {
		return ErrOutboxInvalid
	}
	if prior.StreamID != d.StreamID || prior.Sequence != d.Sequence || prior.EventID != d.EventID || prior.RecordHash != d.RecordHash {
		return ErrOutboxConflict
	}
	if prior.DeliveredAt.IsZero() {
		prior.DeliveredAt = d.DeliveredAt
		if prior.DeliveredAt.IsZero() {
			prior.DeliveredAt = time.Now().UTC()
		}
		a.items[d.DeliveryID] = prior
	}
	return nil
}
func (a *MemoryOutboxAdapter) Deliveries() []Delivery {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Delivery, 0, len(a.items))
	for _, d := range a.items {
		out = append(out, d)
	}
	sort.Slice(out, func(i, k int) bool { return out[i].DeliveryID < out[k].DeliveryID })
	return out
}
func validateDelivery(d Delivery) error {
	if d.DeliveryID == "" || d.Target == "" || d.StreamID == "" || d.EventID == "" || d.Sequence == 0 || !isDigest(d.RecordHash) {
		return ErrOutboxInvalid
	}
	switch d.Target {
	case OutboxTargetPostgres, OutboxTargetWORM, OutboxTargetSIEM:
		return nil
	}
	return ErrOutboxInvalid
}

var _ OutboxContract = (*MemoryOutboxAdapter)(nil)
