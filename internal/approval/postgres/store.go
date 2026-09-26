package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	_ "github.com/jackc/pgx/v5/stdlib"
	"hash/fnv"
	"strings"
)

var ErrInvalidStore = errors.New("invalid approval PostgreSQL store")

type Store struct{ db *sql.DB }

var _ approval.Persistence = (*Store)(nil)
var _ approval.SnapshotPersistence = (*Store)(nil)
var _ approval.EpochSnapshotPersistence = (*Store)(nil)
var _ approval.EpochGuardedPersistence = (*Store)(nil)
var _ approval.AtomicPersistence = (*Store)(nil)
var _ approval.AtomicEpochGuardedPersistence = (*Store)(nil)

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalidStore
	}
	return &Store{db: db}, nil
}
func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("%w: DSN is required", ErrInvalidStore)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrInvalidStore, err)
	}
	s, _ := New(db)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("%w: ping: %v", ErrInvalidStore, err)
	}
	return s, nil
}
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Health verifies that the complete approval persistence surface is usable.
//
// A plain Ping or epoch read can succeed while a revoked grant or a missing
// approvals, events, or idempotency table prevents the Gate from recording a
// decision. The probe deliberately performs the same bounded read/write
// classes used by the approval ledger in one transaction, then rolls it back
// unconditionally so readiness never creates durable approval data.
func (s *Store) Health(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var transactionID string
	if err := tx.QueryRowContext(ctx, "SELECT txid_current()::text").Scan(&transactionID); err != nil {
		return err
	}
	probeID := "approval-readiness-" + transactionID

	// Read every table before attempting writes. These statements also make a
	// missing table or revoked SELECT grant a readiness failure.
	for _, query := range []string{
		"SELECT 1 FROM cheesewaf_approvals LIMIT 1",
		"SELECT 1 FROM cheesewaf_approval_events LIMIT 1",
		"SELECT 1 FROM cheesewaf_approval_idempotency LIMIT 1",
	} {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	var epoch uint64
	if err := tx.QueryRowContext(ctx, "SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1 FOR UPDATE").Scan(&epoch); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return approval.ErrApprovalNotFound
		}
		return err
	}

	// Exercise INSERT grants for the ledger tables and UPDATE permission for
	// the durable epoch checkpoint. Rollback below keeps all rows ephemeral.
	if _, err := tx.ExecContext(ctx, "INSERT INTO cheesewaf_approvals(request_id,record_json,workflow_digest) VALUES($1,'{}'::jsonb,$2)", probeID, probeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE cheesewaf_approvals SET workflow_digest=$2,updated_at=now() WHERE request_id=$1", probeID, probeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cheesewaf_approval_events(request_id,sequence,event_json,event_hash,previous_hash) VALUES($1,1,'{}'::jsonb,$2,'')", probeID, probeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO cheesewaf_approval_idempotency(idempotency_key,request_id,fingerprint) VALUES($1,$2,$3)", probeID, probeID, probeID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE cheesewaf_approval_epoch SET policy_epoch=policy_epoch WHERE id=1"); err != nil {
		return err
	}
	return nil
}

func (s *Store) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	qs := []string{"CREATE TABLE IF NOT EXISTS cheesewaf_approvals (request_id TEXT PRIMARY KEY, record_json JSONB NOT NULL, workflow_digest TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())", "CREATE TABLE IF NOT EXISTS cheesewaf_approval_events (request_id TEXT NOT NULL, sequence BIGINT NOT NULL, event_json JSONB NOT NULL, event_hash TEXT NOT NULL, previous_hash TEXT NOT NULL DEFAULT '', PRIMARY KEY(request_id,sequence))", "CREATE TABLE IF NOT EXISTS cheesewaf_approval_idempotency (idempotency_key TEXT PRIMARY KEY, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL, recorded_at TIMESTAMPTZ NOT NULL DEFAULT now())", "CREATE TABLE IF NOT EXISTS cheesewaf_approval_epoch (id BIGINT PRIMARY KEY CHECK (id=1), policy_epoch BIGINT NOT NULL)"}
	for _, q := range qs {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("%w: migration: %v", ErrInvalidStore, err)
		}
	}
	return tx.Commit()
}

func (s *Store) CompareAndSetEpoch(ctx context.Context, expected, next uint64) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if next < expected {
		return approval.ErrEpochRegression
	}

	// Establishing the initial durable checkpoint is only valid for an
	// expected epoch of zero. Once a checkpoint exists, every later update
	// must match it under a row-level compare-and-set; silently inserting a
	// missing row for a non-zero expected value would otherwise permit a stale
	// Gate to become the durable authority.
	if expected == 0 {
		res, err := s.db.ExecContext(ctx, "INSERT INTO cheesewaf_approval_epoch(id,policy_epoch) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET policy_epoch=EXCLUDED.policy_epoch WHERE cheesewaf_approval_epoch.policy_epoch=$2", next, expected)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return approval.ErrEpochChanged
		}
		return nil
	}

	res, err := s.db.ExecContext(ctx, "UPDATE cheesewaf_approval_epoch SET policy_epoch=$1 WHERE id=1 AND policy_epoch=$2", next, expected)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return approval.ErrEpochChanged
	}
	return nil
}
func (s *Store) PolicyEpoch(ctx context.Context) (uint64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, ErrInvalidStore
	}
	var e uint64
	err := s.db.QueryRowContext(ctx, "SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1").Scan(&e)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, approval.ErrApprovalNotFound
	}
	return e, err
}
func (s *Store) applyMutationTx(ctx context.Context, tx *sql.Tx, expectedEpoch uint64, m approval.ApprovalMutation) error {
	var err error
	if err := approval.ValidateMutationForAdapter(m); err != nil {
		return err
	}
	if m.Record.Request.PolicyEpoch != expectedEpoch {
		return approval.ErrEpochChanged
	}
	m.Event.WorkflowDigest = m.WorkflowDigest
	if m.Event.IntentDigest != "" && m.Event.IntentDigest != m.Record.Request.IntentDigest {
		return approval.ErrBindingConflict
	}
	if m.Event.SessionID != "" && m.Event.SessionID != m.Record.Request.SessionID {
		return approval.ErrBindingConflict
	}
	if m.Event.Nonce != "" && m.Event.Nonce != m.Record.Request.Nonce {
		return approval.ErrBindingConflict
	}
	m.Event.IntentDigest = m.Record.Request.IntentDigest
	m.Event.SessionID = m.Record.Request.SessionID
	m.Event.Nonce = m.Record.Request.Nonce
	if err := lockAndCheckEpoch(ctx, tx, expectedEpoch); err != nil {
		return err
	}
	fp := fingerprint(m)
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey(m.Record.ID)); err != nil {
		return err
	}
	var prior string
	err = tx.QueryRowContext(ctx, "SELECT fingerprint FROM cheesewaf_approval_idempotency WHERE idempotency_key=$1", m.IdempotencyKey).Scan(&prior)
	if err == nil {
		if prior == fp {
			return nil
		}
		return approval.ErrIdempotencyConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var workflow string
	rowErr := tx.QueryRowContext(ctx, "SELECT workflow_digest FROM cheesewaf_approvals WHERE request_id=$1 FOR UPDATE", m.Record.ID).Scan(&workflow)
	exists := rowErr == nil
	if rowErr != nil && !errors.Is(rowErr, sql.ErrNoRows) {
		return rowErr
	}
	if exists && workflow != m.WorkflowDigest {
		return approval.ErrBindingConflict
	}
	if m.Event.Scope != m.Record.Request.Scope || m.Event.PolicyEpoch != m.Record.Request.PolicyEpoch || m.Event.IntentDigest != m.Record.Request.IntentDigest || m.Event.SessionID != m.Record.Request.SessionID || m.Event.Nonce != m.Record.Request.Nonce {
		return approval.ErrBindingConflict
	}
	var seq int64
	var prev string
	evErr := tx.QueryRowContext(ctx, "SELECT sequence,event_hash FROM cheesewaf_approval_events WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1", m.Record.ID).Scan(&seq, &prev)
	if errors.Is(evErr, sql.ErrNoRows) {
		if m.Event.Sequence != 1 {
			return approval.ErrEventSequence
		}
	} else if evErr != nil {
		return evErr
	} else {
		if m.Event.Sequence != uint64(seq+1) {
			return approval.ErrEventSequence
		}
		m.Event.PreviousHash = prev
	}
	m.Event.Hash = hashEvent(m.Event)
	rb, _ := json.Marshal(m.Record)
	eb, _ := json.Marshal(m.Event)
	if exists {
		_, err = tx.ExecContext(ctx, "UPDATE cheesewaf_approvals SET record_json=$2,workflow_digest=$3,updated_at=now() WHERE request_id=$1", m.Record.ID, rb, m.WorkflowDigest)
	} else {
		_, err = tx.ExecContext(ctx, "INSERT INTO cheesewaf_approvals(request_id,record_json,workflow_digest) VALUES($1,$2,$3)", m.Record.ID, rb, m.WorkflowDigest)
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO cheesewaf_approval_events(request_id,sequence,event_json,event_hash,previous_hash) VALUES($1,$2,$3,$4,$5)", m.Record.ID, int64(m.Event.Sequence), eb, m.Event.Hash, m.Event.PreviousHash); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO cheesewaf_approval_idempotency(idempotency_key,request_id,fingerprint) VALUES($1,$2,$3)", m.IdempotencyKey, m.Record.ID, fp); err != nil {
		return err
	}
	return nil
}
func (s *Store) Apply(ctx context.Context, m approval.ApprovalMutation) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.applyMutationTx(ctx, tx, m.Record.Request.PolicyEpoch, m); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplyAtEpoch is the write-time epoch-fenced mutation path used by Gate.
func (s *Store) ApplyAtEpoch(ctx context.Context, expectedEpoch uint64, m approval.ApprovalMutation) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.applyMutationTx(ctx, tx, expectedEpoch, m); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ApplyBatch(ctx context.Context, ms []approval.ApprovalMutation) error {
	if s == nil || s.db == nil || ctx == nil || len(ms) == 0 {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	expectedEpoch := ms[0].Record.Request.PolicyEpoch
	for _, m := range ms {
		if err := s.applyMutationTx(ctx, tx, expectedEpoch, m); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ApplyBatchAtEpoch is the atomic write-time epoch-fenced path used by Gate.
func (s *Store) ApplyBatchAtEpoch(ctx context.Context, expectedEpoch uint64, ms []approval.ApprovalMutation) error {
	if s == nil || s.db == nil || ctx == nil || len(ms) == 0 {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, m := range ms {
		if err := s.applyMutationTx(ctx, tx, expectedEpoch, m); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func lockAndCheckEpoch(ctx context.Context, tx *sql.Tx, expectedEpoch uint64) error {
	var current uint64
	err := tx.QueryRowContext(ctx, "SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1 FOR UPDATE").Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.ErrEpochChanged
	}
	if err != nil {
		return err
	}
	if current != expectedEpoch {
		return approval.ErrEpochChanged
	}
	return nil
}

func (s *Store) Load(ctx context.Context, id string) (approval.Record, error) {
	if s == nil || s.db == nil || ctx == nil {
		return approval.Record{}, ErrInvalidStore
	}
	return s.loadRecord(ctx, s.db, id)
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) loadRecord(ctx context.Context, q rowQuerier, id string) (approval.Record, error) {
	if err := approval.ValidateIdentifier(id); err != nil {
		return approval.Record{}, fmt.Errorf("%w: invalid request id", ErrInvalidStore)
	}
	var b []byte
	err := q.QueryRowContext(ctx, "SELECT record_json FROM cheesewaf_approvals WHERE request_id=$1", id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return approval.Record{}, approval.ErrApprovalNotFound
	}
	if err != nil {
		return approval.Record{}, err
	}
	var r approval.Record
	if err := json.Unmarshal(b, &r); err != nil {
		return approval.Record{}, err
	}
	if err := approval.ValidateRecordForAdapter(r); err != nil {
		return approval.Record{}, fmt.Errorf("%w: invalid persisted record", ErrInvalidStore)
	}
	return r, nil
}

func (s *Store) LoadWithEvents(ctx context.Context, id string) (approval.Record, []approval.AuditEvent, error) {
	if s == nil || s.db == nil || ctx == nil {
		return approval.Record{}, nil, ErrInvalidStore
	}
	return s.loadWithEventsSnapshot(ctx, id, nil)
}

func (s *Store) LoadWithEventsAtEpoch(ctx context.Context, id string, expectedEpoch uint64) (approval.Record, []approval.AuditEvent, error) {
	if s == nil || s.db == nil || ctx == nil {
		return approval.Record{}, nil, ErrInvalidStore
	}
	return s.loadWithEventsSnapshot(ctx, id, &expectedEpoch)
}

func (s *Store) loadWithEventsSnapshot(ctx context.Context, id string, expectedEpoch *uint64) (approval.Record, []approval.AuditEvent, error) {
	// Recovery must see either the record and all events before a writer commits,
	// or the complete post-commit state. Repeatable read gives all recovery
	// queries one PostgreSQL snapshot without changing the write path.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return approval.Record{}, nil, err
	}
	defer tx.Rollback()
	if expectedEpoch != nil {
		persisted, err := s.loadEpoch(ctx, tx)
		if err != nil {
			return approval.Record{}, nil, err
		}
		if persisted != *expectedEpoch {
			return approval.Record{}, nil, approval.ErrEpochChanged
		}
	}
	record, err := s.loadRecord(ctx, tx, id)
	if err != nil {
		return approval.Record{}, nil, err
	}
	events, err := s.loadEvents(ctx, tx, id, record)
	if err != nil {
		return approval.Record{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return approval.Record{}, nil, err
	}
	return record, events, nil
}

func (s *Store) loadEpoch(ctx context.Context, q rowQuerier) (uint64, error) {
	var epoch uint64
	err := q.QueryRowContext(ctx, "SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1").Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, approval.ErrApprovalNotFound
	}
	return epoch, err
}

func (s *Store) Events(ctx context.Context, id string) ([]approval.AuditEvent, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	_, events, err := s.LoadWithEvents(ctx, id)
	if err != nil {
		return nil, err
	}
	return events, nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) loadEvents(ctx context.Context, q queryer, id string, record approval.Record) ([]approval.AuditEvent, error) {
	if err := approval.ValidateIdentifier(id); err != nil {
		return nil, fmt.Errorf("%w: invalid request id", ErrInvalidStore)
	}
	rows, err := q.QueryContext(ctx, "SELECT event_json,event_hash FROM cheesewaf_approval_events WHERE request_id=$1 ORDER BY sequence", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []approval.AuditEvent
	for rows.Next() {
		var b []byte
		var persistedHash string
		var e approval.AuditEvent
		if err := rows.Scan(&b, &persistedHash); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		if e.Sequence != uint64(len(out)+1) || e.RequestID != record.ID {
			return nil, fmt.Errorf("%w: corrupt event chain", ErrInvalidStore)
		}
		if e.Scope != record.Request.Scope || e.PolicyEpoch != record.Request.PolicyEpoch || e.IntentDigest != record.Request.IntentDigest || e.WorkflowDigest != record.Request.WorkflowDigest || e.SessionID != record.Request.SessionID || e.Nonce != record.Request.Nonce {
			return nil, approval.ErrBindingConflict
		}
		if e.PreviousHash != func() string {
			if len(out) == 0 {
				return ""
			}
			return out[len(out)-1].Hash
		}() || e.Hash == "" || persistedHash != e.Hash || hashEvent(e) != e.Hash {
			return nil, fmt.Errorf("%w: corrupt event chain", ErrInvalidStore)
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, approval.ErrApprovalNotFound
	}
	return out, rows.Err()
}

// ListIDs returns durable approval IDs in stable order for startup recovery.
func (s *Store) ListIDs(ctx context.Context) ([]string, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	rows, err := s.db.QueryContext(ctx, "SELECT request_id FROM cheesewaf_approvals ORDER BY request_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func fingerprint(m approval.ApprovalMutation) string {
	b, _ := json.Marshal(m)
	return approval.HashBytes(b)
}
func hashEvent(e approval.AuditEvent) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	return approval.HashBytes(b)
}
func lockKey(v string) int64 {
	h := fnv.New64a()
	h.Write([]byte(v))
	return int64(h.Sum64() & 0x7fffffffffffffff)
}
