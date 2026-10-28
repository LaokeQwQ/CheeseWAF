package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PostgresJournal persists each chain commit and its outbox rows atomically.
// The caller owns db and must apply Migrate before constructing a Runtime.
type PostgresJournal struct {
	db *sql.DB
}

func NewPostgresJournal(db *sql.DB) (*PostgresJournal, error) {
	if db == nil {
		return nil, ErrUnavailable
	}
	return &PostgresJournal{db: db}, nil
}

func (j *PostgresJournal) Durable() bool { return j != nil && j.db != nil }

func (j *PostgresJournal) Migrate(ctx context.Context) error {
	if !j.Durable() {
		return ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cheesewaf_audit_streams (
			stream_id TEXT PRIMARY KEY,
			head_sequence BIGINT NOT NULL DEFAULT 0 CHECK (head_sequence >= 0),
			head_hash TEXT NOT NULL DEFAULT '',
			CHECK ((head_sequence = 0 AND head_hash = '') OR (head_sequence > 0 AND head_hash ~ '^[0-9a-f]{64}$'))
		)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_audit_records (
			stream_id TEXT NOT NULL REFERENCES cheesewaf_audit_streams(stream_id),
			sequence BIGINT NOT NULL CHECK (sequence > 0),
			event_id TEXT NOT NULL,
			record_hash TEXT NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
			commit_json BYTEA NOT NULL,
			PRIMARY KEY (stream_id, sequence),
			UNIQUE (stream_id, event_id)
		)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_audit_outbox (
			delivery_id TEXT PRIMARY KEY,
			target TEXT NOT NULL CHECK (target IN ('postgres', 'worm', 'siem')),
			stream_id TEXT NOT NULL,
			sequence BIGINT NOT NULL CHECK (sequence > 0),
			event_id TEXT NOT NULL,
			record_hash TEXT NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
			created_at TIMESTAMPTZ NOT NULL,
			delivered_at TIMESTAMPTZ,
			UNIQUE (stream_id, sequence, target),
			FOREIGN KEY (stream_id, sequence) REFERENCES cheesewaf_audit_records(stream_id, sequence)
		)`,
		`CREATE OR REPLACE FUNCTION cheesewaf_audit_records_immutable() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'audit records are append-only' USING ERRCODE = '55000';
		END;
		$$ LANGUAGE plpgsql`,
		`DO $$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger
				WHERE tgname = 'cheesewaf_audit_records_immutable'
				AND tgrelid = 'cheesewaf_audit_records'::regclass
				AND NOT tgisinternal
			) THEN
				CREATE TRIGGER cheesewaf_audit_records_immutable
				BEFORE UPDATE OR DELETE ON cheesewaf_audit_records
				FOR EACH ROW EXECUTE FUNCTION cheesewaf_audit_records_immutable();
			END IF;
		END $$`,
		`CREATE OR REPLACE FUNCTION cheesewaf_audit_outbox_identity_immutable() RETURNS trigger AS $$
		BEGIN
			IF ROW(NEW.delivery_id, NEW.target, NEW.stream_id, NEW.sequence, NEW.event_id, NEW.record_hash, NEW.created_at)
				IS DISTINCT FROM ROW(OLD.delivery_id, OLD.target, OLD.stream_id, OLD.sequence, OLD.event_id, OLD.record_hash, OLD.created_at) THEN
				RAISE EXCEPTION 'audit outbox identity is immutable' USING ERRCODE = '55000';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`DO $$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger
				WHERE tgname = 'cheesewaf_audit_outbox_identity_immutable'
				AND tgrelid = 'cheesewaf_audit_outbox'::regclass
				AND NOT tgisinternal
			) THEN
				CREATE TRIGGER cheesewaf_audit_outbox_identity_immutable
				BEFORE UPDATE ON cheesewaf_audit_outbox
				FOR EACH ROW EXECUTE FUNCTION cheesewaf_audit_outbox_identity_immutable();
			END IF;
		END $$`,
		`CREATE OR REPLACE FUNCTION cheesewaf_audit_outbox_no_delete() RETURNS trigger AS $$
		BEGIN
			RAISE EXCEPTION 'audit outbox is append-only' USING ERRCODE = '55000';
		END;
		$$ LANGUAGE plpgsql`,
		`DO $$ BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_trigger
				WHERE tgname = 'cheesewaf_audit_outbox_no_delete'
				AND tgrelid = 'cheesewaf_audit_outbox'::regclass
				AND NOT tgisinternal
			) THEN
				CREATE TRIGGER cheesewaf_audit_outbox_no_delete
				BEFORE DELETE ON cheesewaf_audit_outbox
				FOR EACH ROW EXECUTE FUNCTION cheesewaf_audit_outbox_no_delete();
			END IF;
		END $$`,
	}
	for _, statement := range statements {
		if _, err := j.db.ExecContext(ctx, statement); err != nil {
			return journalDBError(ctx, "migrate")
		}
	}
	return nil
}

func (j *PostgresJournal) Append(ctx context.Context, commit Commit) error {
	if !j.Durable() {
		return ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateCommit(commit); err != nil {
		return err
	}
	if commit.Record.Sequence > uint64(1<<63-1) {
		return ErrInvalidRecord
	}
	body, err := json.Marshal(cloneCommit(commit))
	if err != nil {
		return ErrInvalidRecord
	}
	tx, err := j.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return journalDBError(ctx, "begin append")
	}
	defer tx.Rollback()

	stream := commit.Record.Event.StreamID
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_audit_streams(stream_id) VALUES($1) ON CONFLICT(stream_id) DO NOTHING`, stream); err != nil {
		return journalDBError(ctx, "prepare stream")
	}
	var headSequence int64
	var headHash string
	if err := tx.QueryRowContext(ctx, `SELECT head_sequence, head_hash FROM cheesewaf_audit_streams WHERE stream_id=$1 FOR UPDATE`, stream).Scan(&headSequence, &headHash); err != nil {
		return journalDBError(ctx, "lock stream")
	}
	sequence := commit.Record.Sequence
	if sequence <= uint64(headSequence) {
		var prior []byte
		err := tx.QueryRowContext(ctx, `SELECT commit_json FROM cheesewaf_audit_records WHERE stream_id=$1 AND sequence=$2`, stream, int64(sequence)).Scan(&prior)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCorruptChain
		}
		if err != nil {
			return journalDBError(ctx, "read replay")
		}
		if !bytes.Equal(prior, body) {
			return ErrReplayConflict
		}
		if err := tx.Commit(); err != nil {
			return journalDBError(ctx, "commit replay")
		}
		return nil
	}
	if sequence != uint64(headSequence)+1 || commit.Record.PreviousHash != headHash {
		return ErrSequenceConflict
	}
	var eventExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cheesewaf_audit_records WHERE stream_id=$1 AND event_id=$2)`, stream, commit.Record.Event.EventID).Scan(&eventExists); err != nil {
		return journalDBError(ctx, "check event id")
	}
	if eventExists {
		return ErrReplayConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_audit_records(stream_id, sequence, event_id, record_hash, commit_json) VALUES($1,$2,$3,$4,$5)`, stream, int64(sequence), commit.Record.Event.EventID, commit.Record.Hash, body); err != nil {
		return journalDBError(ctx, "insert record")
	}
	for _, delivery := range commit.Outbox {
		result, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_audit_outbox(delivery_id, target, stream_id, sequence, event_id, record_hash, created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, delivery.DeliveryID, string(delivery.Target), delivery.StreamID, int64(delivery.Sequence), delivery.EventID, delivery.RecordHash, delivery.CreatedAt.UTC())
		if err != nil {
			return journalDBError(ctx, "insert outbox")
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return journalDBError(ctx, "inspect outbox insert")
		}
		if inserted == 0 {
			var prior Delivery
			var target string
			err := tx.QueryRowContext(ctx, `SELECT delivery_id,target,stream_id,sequence,event_id,record_hash,created_at,COALESCE(delivered_at,'0001-01-01T00:00:00Z'::timestamptz)
				FROM cheesewaf_audit_outbox WHERE delivery_id=$1 OR (stream_id=$2 AND sequence=$3 AND target=$4)`, delivery.DeliveryID, delivery.StreamID, int64(delivery.Sequence), string(delivery.Target)).
				Scan(&prior.DeliveryID, &target, &prior.StreamID, &prior.Sequence, &prior.EventID, &prior.RecordHash, &prior.CreatedAt, &prior.DeliveredAt)
			if err != nil {
				return journalDBError(ctx, "read outbox conflict")
			}
			prior.Target = OutboxTarget(target)
			if !deliveryIdentityEqual(prior, delivery) {
				return ErrOutboxConflict
			}
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE cheesewaf_audit_streams SET head_sequence=$2,head_hash=$3 WHERE stream_id=$1 AND head_sequence=$4 AND head_hash=$5`, stream, int64(sequence), commit.Record.Hash, headSequence, headHash)
	if err != nil {
		return journalDBError(ctx, "advance stream")
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return journalDBError(ctx, "inspect stream update")
	}
	if updated != 1 {
		return ErrSequenceConflict
	}
	if err := tx.Commit(); err != nil {
		return journalDBError(ctx, "commit append")
	}
	return nil
}

// Records pages the stream with a targeted query. Full-chain verification is a
// separate, explicit operation (Verify), so a one-record page never loads the
// whole journal.
func (j *PostgresJournal) Records(ctx context.Context, stream string, after uint64, limit int) ([]Record, error) {
	if !j.Durable() {
		return nil, ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	query := `SELECT sequence, commit_json FROM cheesewaf_audit_records WHERE stream_id=$1 AND sequence>$2 ORDER BY sequence ASC`
	args := []any{stream, int64(after)}
	if limit > 0 {
		query += ` LIMIT $3`
		args = append(args, limit)
	}
	rows, err := j.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, journalDBError(ctx, "page records")
	}
	defer rows.Close()
	result := make([]Record, 0, 8)
	for rows.Next() {
		var sequence int64
		var raw []byte
		if err := rows.Scan(&sequence, &raw); err != nil {
			return nil, journalDBError(ctx, "scan record")
		}
		var commit Commit
		if decodeStrict(raw, &commit) != nil || uint64(sequence) != commit.Record.Sequence ||
			commit.Record.Event.StreamID != stream || validateCommit(commit) != nil {
			return nil, ErrCorruptChain
		}
		result = append(result, cloneRecord(commit.Record))
	}
	if err := rows.Err(); err != nil {
		return nil, journalDBError(ctx, "iterate records")
	}
	return result, nil
}

func (j *PostgresJournal) Last(ctx context.Context, stream string) (Record, error) {
	if !j.Durable() {
		return Record{}, ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	var sequence int64
	var raw []byte
	err := j.db.QueryRowContext(ctx, `SELECT sequence, commit_json FROM cheesewaf_audit_records WHERE stream_id=$1 ORDER BY sequence DESC LIMIT 1`, stream).Scan(&sequence, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, nil
	}
	if err != nil {
		return Record{}, journalDBError(ctx, "read last record")
	}
	var commit Commit
	if decodeStrict(raw, &commit) != nil || uint64(sequence) != commit.Record.Sequence ||
		commit.Record.Event.StreamID != stream || validateCommit(commit) != nil {
		return Record{}, ErrCorruptChain
	}
	return cloneRecord(commit.Record), nil
}

func (j *PostgresJournal) Checkpoint(ctx context.Context, stream string, sequence uint64) (*Checkpoint, error) {
	if !j.Durable() {
		return nil, ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if sequence == 0 || sequence > uint64(1<<63-1) {
		return nil, nil
	}
	var storedSequence int64
	var eventID, recordHash string
	var raw []byte
	err := j.db.QueryRowContext(ctx, `SELECT sequence,event_id,record_hash,commit_json FROM cheesewaf_audit_records WHERE stream_id=$1 AND sequence=$2`, stream, int64(sequence)).
		Scan(&storedSequence, &eventID, &recordHash, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, journalDBError(ctx, "read checkpoint")
	}
	var commit Commit
	if decodeStrict(raw, &commit) != nil || storedSequence <= 0 || uint64(storedSequence) != sequence ||
		commit.Record.Sequence != sequence || commit.Record.Event.StreamID != stream ||
		commit.Record.Event.EventID != eventID || commit.Record.Hash != recordHash || validateCommit(commit) != nil {
		return nil, ErrCorruptChain
	}
	if commit.Checkpoint == nil {
		return nil, nil
	}
	copy := *commit.Checkpoint
	copy.Signature = append([]byte(nil), commit.Checkpoint.Signature...)
	return &copy, nil
}

func (j *PostgresJournal) PendingOutbox(ctx context.Context, stream string, limit int) ([]Delivery, error) {
	if !j.Durable() {
		return nil, ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	query := `SELECT delivery_id,target,stream_id,sequence,event_id,record_hash,created_at FROM cheesewaf_audit_outbox WHERE stream_id=$1 AND delivered_at IS NULL ORDER BY sequence,target`
	args := []any{stream}
	if limit > 0 {
		query += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := j.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, journalDBError(ctx, "read pending outbox")
	}
	defer rows.Close()
	result := make([]Delivery, 0)
	for rows.Next() {
		var delivery Delivery
		var target string
		var sequence int64
		if err := rows.Scan(&delivery.DeliveryID, &target, &delivery.StreamID, &sequence, &delivery.EventID, &delivery.RecordHash, &delivery.CreatedAt); err != nil {
			return nil, journalDBError(ctx, "decode pending outbox")
		}
		if sequence <= 0 {
			return nil, ErrCorruptChain
		}
		delivery.Target = OutboxTarget(target)
		delivery.Sequence = uint64(sequence)
		if validateDelivery(delivery) != nil {
			return nil, ErrCorruptChain
		}
		result = append(result, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, journalDBError(ctx, "iterate pending outbox")
	}
	return result, nil
}

func (j *PostgresJournal) AckOutbox(ctx context.Context, delivery Delivery) error {
	if !j.Durable() {
		return ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if validateDelivery(delivery) != nil {
		return ErrOutboxInvalid
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return journalDBError(ctx, "begin outbox ack")
	}
	defer tx.Rollback()
	var prior Delivery
	var target string
	var sequence int64
	var deliveredAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT delivery_id,target,stream_id,sequence,event_id,record_hash,created_at,delivered_at FROM cheesewaf_audit_outbox WHERE delivery_id=$1 FOR UPDATE`, delivery.DeliveryID).
		Scan(&prior.DeliveryID, &target, &prior.StreamID, &sequence, &prior.EventID, &prior.RecordHash, &prior.CreatedAt, &deliveredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return journalDBError(ctx, "read outbox ack")
	}
	prior.Target = OutboxTarget(target)
	if deliveredAt.Valid {
		prior.DeliveredAt = deliveredAt.Time
	}
	if sequence <= 0 {
		return ErrCorruptChain
	}
	prior.Sequence = uint64(sequence)
	if !deliveryIdentityEqual(prior, delivery) {
		return ErrOutboxConflict
	}
	if prior.DeliveredAt.IsZero() {
		at := delivery.DeliveredAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE cheesewaf_audit_outbox SET delivered_at=$2 WHERE delivery_id=$1`, delivery.DeliveryID, at.UTC()); err != nil {
			return journalDBError(ctx, "mark outbox delivered")
		}
	}
	if err := tx.Commit(); err != nil {
		return journalDBError(ctx, "commit outbox ack")
	}
	return nil
}

// verifyPageSize bounds how many commits are verified at once. Verification
// pages the chain instead of loading the whole journal, so memory stays flat
// as the audit grows.
const verifyPageSize = 2000

func (j *PostgresJournal) Verify(ctx context.Context, stream string) error {
	if !j.Durable() {
		return ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	after := uint64(0)
	previousHash := ""
	for {
		rows, err := j.db.QueryContext(ctx, `SELECT sequence, commit_json FROM cheesewaf_audit_records WHERE stream_id=$1 AND sequence>$2 ORDER BY sequence ASC LIMIT $3`, stream, int64(after), verifyPageSize)
		if err != nil {
			return journalDBError(ctx, "verify records")
		}
		count := 0
		for rows.Next() {
			var sequence int64
			var raw []byte
			if err := rows.Scan(&sequence, &raw); err != nil {
				rows.Close()
				return journalDBError(ctx, "verify scan")
			}
			var commit Commit
			if decodeStrict(raw, &commit) != nil || uint64(sequence) != after+1 || uint64(sequence) != commit.Record.Sequence ||
				commit.Record.Event.StreamID != stream || commit.Record.PreviousHash != previousHash || validateCommit(commit) != nil {
				rows.Close()
				return ErrCorruptChain
			}
			previousHash = commit.Record.Hash
			after = uint64(sequence)
			count++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return journalDBError(ctx, "verify iterate")
		}
		rows.Close()
		if count < verifyPageSize {
			var headSequence int64
			var headHash string
			err := j.db.QueryRowContext(ctx, `SELECT head_sequence, head_hash FROM cheesewaf_audit_streams WHERE stream_id=$1`, stream).Scan(&headSequence, &headHash)
			if errors.Is(err, sql.ErrNoRows) {
				if after == 0 {
					return nil
				}
				return ErrCorruptChain
			}
			if err != nil {
				return journalDBError(ctx, "read verified head")
			}
			if uint64(headSequence) != after || headHash != previousHash {
				return ErrCorruptChain
			}
			return nil
		}
	}
}

func (j *PostgresJournal) Flush(ctx context.Context) error {
	if !j.Durable() {
		return ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := j.db.PingContext(ctx); err != nil {
		return journalDBError(ctx, "flush")
	}
	return nil
}

func (j *PostgresJournal) readCommits(ctx context.Context, stream string) ([]Commit, error) {
	if !j.Durable() {
		return nil, ErrUnavailable
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	tx, err := j.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, journalDBError(ctx, "begin chain read")
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT sequence,event_id,record_hash,commit_json FROM cheesewaf_audit_records WHERE stream_id=$1 ORDER BY sequence`, stream)
	if err != nil {
		return nil, journalDBError(ctx, "read chain")
	}
	defer rows.Close()
	commits := make([]Commit, 0)
	for rows.Next() {
		var sequence int64
		var eventID, recordHash string
		var raw []byte
		if err := rows.Scan(&sequence, &eventID, &recordHash, &raw); err != nil {
			return nil, journalDBError(ctx, "decode chain row")
		}
		var commit Commit
		if decodeStrict(raw, &commit) != nil || sequence <= 0 || commit.Record.Sequence != uint64(sequence) ||
			commit.Record.Event.StreamID != stream || commit.Record.Event.EventID != eventID || commit.Record.Hash != recordHash {
			return nil, ErrCorruptChain
		}
		commits = append(commits, commit)
	}
	if err := rows.Err(); err != nil {
		return nil, journalDBError(ctx, "iterate chain")
	}
	if err := verifyCommits(commits); err != nil {
		return nil, ErrCorruptChain
	}
	var headSequence int64
	var headHash string
	err = tx.QueryRowContext(ctx, `SELECT head_sequence,head_hash FROM cheesewaf_audit_streams WHERE stream_id=$1`, stream).Scan(&headSequence, &headHash)
	if errors.Is(err, sql.ErrNoRows) {
		if len(commits) == 0 {
			if err := tx.Commit(); err != nil {
				return nil, journalDBError(ctx, "commit chain read")
			}
			return commits, nil
		}
		return nil, ErrCorruptChain
	}
	if err != nil {
		return nil, journalDBError(ctx, "read stream head")
	}
	if headSequence < 0 || uint64(headSequence) != uint64(len(commits)) {
		return nil, ErrCorruptChain
	}
	if headSequence == 0 {
		if headHash != "" {
			return nil, ErrCorruptChain
		}
	} else if headHash != commits[len(commits)-1].Record.Hash {
		return nil, ErrCorruptChain
	}
	if err := tx.Commit(); err != nil {
		return nil, journalDBError(ctx, "commit chain read")
	}
	return commits, nil
}

func journalDBError(ctx context.Context, operation string) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, operation)
}

var _ Journal = (*PostgresJournal)(nil)
