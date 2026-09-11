// Package audit provides a metadata-only, append-only audit runtime. Event
// schemas intentionally cannot carry request bodies, secrets, or arbitrary maps.
package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type EventClass string

const (
	EventClassCritical EventClass = "critical"
	EventClassNormal   EventClass = "normal"
)

type EventType string

const (
	EventTypeConfigChanged EventType = "config.changed"
	EventTypeAuthorization EventType = "authorization"
	EventTypeLeaseChanged  EventType = "lease.changed"
	EventTypeUpload        EventType = "upload"
	EventTypeReplication   EventType = "replication"
	EventTypeRetention     EventType = "retention"
	EventTypeRecovery      EventType = "recovery"
	EventTypeAudit         EventType = "audit"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
	OutcomeStarted Outcome = "started"
)

// Event contains opaque identifiers and enumerated codes. Resource is an
// internal resource reference, never a URL, query string, request, or response.
// Reason is a reason code (for example "policy.denied"), not free-form text.
// Credential references must identify the credential record, never its value.
type Event struct {
	EventID        string     `json:"event_id"`
	StreamID       string     `json:"stream_id"`
	TenantID       string     `json:"tenant_id"`
	Actor          string     `json:"actor"`
	Type           EventType  `json:"type"`
	Action         string     `json:"action"`
	Resource       string     `json:"resource"`
	Outcome        Outcome    `json:"outcome"`
	CorrelationID  string     `json:"correlation_id,omitempty"`
	SessionID      string     `json:"session_id,omitempty"`
	LeaseID        string     `json:"lease_id,omitempty"`
	ConfirmationID string     `json:"confirmation_id,omitempty"`
	Reason         string     `json:"reason,omitempty"`
	EvidenceDigest string     `json:"evidence_digest,omitempty"`
	PolicyEpoch    uint64     `json:"policy_epoch"`
	Class          EventClass `json:"class"`
	At             time.Time  `json:"at"`
}

type Record struct {
	Sequence     uint64 `json:"sequence"`
	Event        Event  `json:"event"`
	PreviousHash string `json:"previous_hash,omitempty"`
	Hash         string `json:"hash"`
}

// Commit is persisted atomically: a record must not become visible without
// its checkpoint and all configured outbox destinations.
type Commit struct {
	Record     Record      `json:"record"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
	Outbox     []Delivery  `json:"outbox,omitempty"`
}

type Checkpoint struct {
	StreamID  string    `json:"stream_id"`
	Sequence  uint64    `json:"sequence"`
	Hash      string    `json:"hash"`
	KeyID     string    `json:"key_id"`
	Signature []byte    `json:"signature"`
	At        time.Time `json:"at"`
}

var (
	ErrInvalidEvent      = errors.New("invalid audit event")
	ErrInvalidRecord     = errors.New("invalid audit record")
	ErrCorruptChain      = errors.New("audit hash chain is corrupt")
	ErrReplayConflict    = errors.New("audit replay conflicts with existing content")
	ErrSequenceConflict  = errors.New("audit sequence conflict")
	ErrCheckpointInvalid = errors.New("invalid audit checkpoint")
	ErrSignerUnavailable = errors.New("audit checkpoint signer unavailable")
	ErrNoDurableChannel  = errors.New("critical audit event has no durable channel")
	ErrUnavailable       = errors.New("audit persistence is unavailable")
	ErrQueueFull         = errors.New("audit asynchronous queue is full")
	ErrClosed            = errors.New("audit runtime is closed")
	ErrSpoolCorrupt      = errors.New("encrypted audit spool entry is corrupt")
	ErrOutboxConflict    = errors.New("audit outbox idempotency conflict")
	ErrOutboxInvalid     = errors.New("invalid audit outbox delivery")
)

// DecodeEvent rejects unknown fields and trailing JSON without including input
// values in its errors. In particular, secret/body/payload fields are rejected.
func DecodeEvent(raw []byte) (Event, error) {
	if len(raw) > 8192 {
		return Event{}, ErrInvalidEvent
	}
	var e Event
	if decodeStrict(raw, &e) != nil || validateEvent(e) != nil {
		return Event{}, ErrInvalidEvent
	}
	return e, nil
}

func validateEvent(e Event) error {
	required := []string{e.EventID, e.StreamID, e.TenantID, e.Actor, string(e.Type), e.Action, e.Resource}
	for _, v := range required {
		if !validID(v, false) {
			return ErrInvalidEvent
		}
	}
	optional := []string{e.CorrelationID, e.SessionID, e.LeaseID, e.ConfirmationID, e.Reason}
	for _, v := range optional {
		if !validID(v, true) {
			return ErrInvalidEvent
		}
	}
	if e.Class != EventClassCritical && e.Class != EventClassNormal {
		return ErrInvalidEvent
	}
	switch e.Outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeDenied, OutcomeStarted:
	default:
		return ErrInvalidEvent
	}
	if e.At.IsZero() || e.At.Year() < 1 || e.At.Year() > 9999 || e.PolicyEpoch == 0 {
		return ErrInvalidEvent
	}
	if e.EvidenceDigest != "" && !isDigest(e.EvidenceDigest) {
		return ErrInvalidEvent
	}
	return nil
}

// Strict ASCII identifiers reject whitespace, control/format characters and
// body/query syntax instead of silently rewriting an actor or tenant identity.
func validID(v string, optional bool) bool {
	if v == "" {
		return optional
	}
	if len(v) > 256 {
		return false
	}
	for _, c := range v {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-:@/", c) {
			continue
		}
		return false
	}
	return !strings.Contains(v, "://")
}

func isDigest(v string) bool {
	if len(v) != sha256.Size*2 || v != strings.ToLower(v) {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

func hashRecord(r Record) string {
	e := r.Event
	e.At = e.At.UTC().Round(0)
	b, _ := json.Marshal(struct {
		Domain       string `json:"domain"`
		Sequence     uint64 `json:"sequence"`
		Event        Event  `json:"event"`
		PreviousHash string `json:"previous_hash"`
	}{"cheesewaf.audit.record.v1", r.Sequence, e, r.PreviousHash})
	return hashBytes(b)
}

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func eventEqual(a, b Event) bool {
	a.At = a.At.UTC().Round(0)
	b.At = b.At.UTC().Round(0)
	return a == b
}

func validateRecord(r Record) error {
	if r.Sequence == 0 || !isDigest(r.Hash) || validateEvent(r.Event) != nil {
		return ErrInvalidRecord
	}
	if r.Sequence == 1 && r.PreviousHash != "" || r.Sequence > 1 && !isDigest(r.PreviousHash) {
		return ErrInvalidRecord
	}
	if hashRecord(r) != r.Hash {
		return ErrInvalidRecord
	}
	return nil
}

func checkpointMessage(cp Checkpoint) []byte {
	b, _ := json.Marshal(struct {
		Domain   string    `json:"domain"`
		StreamID string    `json:"stream_id"`
		Sequence uint64    `json:"sequence"`
		Hash     string    `json:"hash"`
		KeyID    string    `json:"key_id"`
		At       time.Time `json:"at"`
	}{"cheesewaf.audit.checkpoint.v1", cp.StreamID, cp.Sequence, cp.Hash, cp.KeyID, cp.At.UTC().Round(0)})
	return b
}

type Signer interface {
	KeyID() string
	Sign([]byte) ([]byte, error)
}
type Ed25519Signer struct {
	ID         string
	PrivateKey ed25519.PrivateKey
}

func (s Ed25519Signer) KeyID() string { return s.ID }
func (s Ed25519Signer) Sign(message []byte) ([]byte, error) {
	if !validID(s.ID, false) || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return nil, ErrSignerUnavailable
	}
	return ed25519.Sign(s.PrivateKey, message), nil
}

func checkpointShape(r Record, cp Checkpoint) error {
	if cp.StreamID != r.Event.StreamID || cp.Sequence != r.Sequence || cp.Hash != r.Hash || !validID(cp.KeyID, false) || len(cp.Signature) != ed25519.SignatureSize || cp.At.IsZero() {
		return ErrCheckpointInvalid
	}
	return nil
}

func VerifyCheckpoint(stream string, r Record, cp Checkpoint, keys map[string]ed25519.PublicKey) error {
	if validateRecord(r) != nil || r.Event.StreamID != stream || checkpointShape(r, cp) != nil {
		return ErrCheckpointInvalid
	}
	key := keys[cp.KeyID]
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, checkpointMessage(cp), cp.Signature) {
		return ErrCheckpointInvalid
	}
	return nil
}

func validateCommit(c Commit) error {
	if err := validateRecord(c.Record); err != nil {
		return err
	}
	if c.Checkpoint != nil {
		if err := checkpointShape(c.Record, *c.Checkpoint); err != nil {
			return err
		}
	}
	seen := make(map[OutboxTarget]bool)
	for _, d := range c.Outbox {
		if validateDelivery(d) != nil || d.StreamID != c.Record.Event.StreamID || d.Sequence != c.Record.Sequence || d.EventID != c.Record.Event.EventID || d.RecordHash != c.Record.Hash || seen[d.Target] {
			return ErrOutboxInvalid
		}
		seen[d.Target] = true
	}
	return nil
}

func cloneCommit(c Commit) Commit {
	if c.Checkpoint != nil {
		cp := *c.Checkpoint
		cp.Signature = append([]byte(nil), cp.Signature...)
		c.Checkpoint = &cp
	}
	c.Outbox = append([]Delivery(nil), c.Outbox...)
	return c
}
func commitEqual(a, b Commit) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func contextErr(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
