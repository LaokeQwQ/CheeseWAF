package diagnostics

import (
	"context"
	"time"
)

// StateCanceled is a terminal state used by durable adapters; Broker keeps its
// existing in-memory transition API unchanged.
const StateCanceled State = "canceled"

// Record is metadata for a diagnostic upload. It intentionally has no package
// or ciphertext fields; encrypted bytes remain in the local queue/object store.
type Record struct {
	UploadID, TenantID, PluginID, PluginVersion    string
	Risk, FairKey, Target, LeaseID, IdempotencyKey string
	PolicyEpoch                                    uint64
	SHA256Digest                                   string
	State                                          State
	Attempt, MaxAttempts                           int
	Bytes                                          int64
	ExpiresAt, CreatedAt, UpdatedAt                time.Time
	LastError, Summary                             string
	LeaseOwner                                     string
	LeaseExpiresAt                                 time.Time
}

// Outbox contains delivery metadata only, never an upload payload.
type Outbox struct {
	EventID, UploadID, Kind, State      string
	Attempt                             int
	AvailableAt, CreatedAt, DeliveredAt time.Time
	LeaseOwner                          string
}

// MetadataPersistence is the optional durable boundary. Implementations must
// keep encrypted package bytes outside this contract.
type MetadataPersistence interface {
	Put(context.Context, Record) (Record, error)
	Get(context.Context, string) (Record, error)
	Claim(context.Context, string, time.Duration) (*Record, error)
	Retry(context.Context, string, string) error
	Cancel(context.Context, string, string) error
	AppendOutbox(context.Context, Outbox) error
	PendingOutbox(context.Context, int) ([]Outbox, error)
	MarkOutboxDelivered(context.Context, string, string) error
}
