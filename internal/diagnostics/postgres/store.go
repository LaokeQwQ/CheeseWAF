// Package postgres provides an opt-in metadata persistence adapter for diagnostics.
// It never stores diagnostic package bytes or ciphertext.
package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	ErrInvalidStore  = errors.New("invalid diagnostics PostgreSQL store")
	ErrInvalidRecord = errors.New("invalid diagnostics metadata record")
	ErrNotFound      = diagnostics.ErrNotFound
	ErrLeaseConflict = errors.New("diagnostics lease conflict")
	ErrStateConflict = errors.New("diagnostics state conflict")
)

const (
	// Reason codes are intentionally short, fixed ASCII values. The caller's
	// reason is an untrusted diagnostic detail and must never cross the
	// PostgreSQL metadata boundary.
	maxReasonCodeLength  = 64
	maxReasonInputLength = 512
)

var sensitiveReasonMarkers = [...]string{
	"secret",
	"token",
	"password",
	"cookie",
	"authorization",
	"credential",
	"private_key",
	"privatekey",
	"dsn=",
	"postgres://",
	"postgresql://",
}

type Store struct{ db *sql.DB }

var _ diagnostics.MetadataPersistence = (*Store)(nil)

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
		return nil, fmt.Errorf("%w: %v", ErrInvalidStore, err)
	}
	s, err := New(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
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

func (s *Store) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin: %v", ErrInvalidStore, err)
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cheesewaf_diagnostic_metadata (upload_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, plugin_id TEXT NOT NULL, plugin_version TEXT NOT NULL, risk TEXT NOT NULL, fair_key TEXT NOT NULL, target TEXT NOT NULL, policy_epoch BIGINT NOT NULL, lease_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, sha256_digest TEXT NOT NULL CHECK (sha256_digest ~ '^[0-9a-f]{64}$'), state TEXT NOT NULL, attempt INT NOT NULL CHECK (attempt >= 0), max_attempts INT NOT NULL CHECK (max_attempts > 0), bytes BIGINT NOT NULL CHECK (bytes >= 0), expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL, last_error TEXT NOT NULL DEFAULT '', summary TEXT NOT NULL DEFAULT '', lease_owner TEXT NOT NULL DEFAULT '', lease_expires_at TIMESTAMPTZ, UNIQUE (tenant_id,idempotency_key))`,
		`CREATE INDEX IF NOT EXISTS cheesewaf_diagnostic_claim_idx ON cheesewaf_diagnostic_metadata (state, expires_at, tenant_id, plugin_id, risk, fair_key)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_diagnostic_outbox (event_id TEXT PRIMARY KEY, upload_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, attempt INT NOT NULL DEFAULT 0, available_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL, delivered_at TIMESTAMPTZ, lease_owner TEXT NOT NULL DEFAULT '')`,
		`CREATE INDEX IF NOT EXISTS cheesewaf_diagnostic_outbox_pending_idx ON cheesewaf_diagnostic_outbox (state, available_at)`,
	}
	for _, q := range statements {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("%w: migration: %v", ErrInvalidStore, err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit: %v", ErrInvalidStore, err)
	}
	return nil
}

func ValidateRecord(r diagnostics.Record) error {
	if !validMetadataIdentifier(r.UploadID) || !validMetadataIdentifier(r.TenantID) || !validMetadataIdentifier(r.PluginID) || !validMetadataIdentifier(r.PluginVersion) || !validMetadataIdentifier(r.Risk) || !validMetadataIdentifier(r.Target) || !validMetadataIdentifier(r.LeaseID) || !validMetadataIdentifier(r.IdempotencyKey) || len(r.SHA256Digest) != 64 || r.SHA256Digest != strings.ToLower(r.SHA256Digest) || r.State == "" || r.Attempt < 0 || r.MaxAttempts <= 0 || r.Bytes < 0 || r.ExpiresAt.IsZero() {
		return ErrInvalidRecord
	}
	for _, c := range r.SHA256Digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalidRecord
		}
	}
	return nil
}

func (s *Store) Put(ctx context.Context, r diagnostics.Record) (diagnostics.Record, error) {
	if s == nil || s.db == nil || ctx == nil {
		return diagnostics.Record{}, ErrInvalidStore
	}
	if err := ValidateRecord(r); err != nil {
		return diagnostics.Record{}, err
	}
	if strings.TrimSpace(r.FairKey) == "" {
		r.FairKey = r.TenantID + "/" + r.PluginID
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return diagnostics.Record{}, fmt.Errorf("%w: begin: %v", ErrInvalidStore, err)
	}
	defer tx.Rollback()
	var prior diagnostics.Record
	err = scanRecord(tx.QueryRowContext(ctx, selectMetadata+` WHERE tenant_id=$1 AND idempotency_key=$2`, r.TenantID, r.IdempotencyKey), &prior)
	if err == nil {
		if recordFingerprint(prior) != recordFingerprint(r) {
			return diagnostics.Record{}, diagnostics.ErrIdempotencyConflict
		}
		if err = tx.Commit(); err != nil {
			return diagnostics.Record{}, err
		}
		return prior, nil
	}
	if !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, ErrNotFound) {
		return diagnostics.Record{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO cheesewaf_diagnostic_metadata (upload_id,tenant_id,plugin_id,plugin_version,risk,fair_key,target,policy_epoch,lease_id,idempotency_key,sha256_digest,state,attempt,max_attempts,bytes,expires_at,created_at,updated_at,last_error,summary,lease_owner,lease_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`, r.UploadID, r.TenantID, r.PluginID, r.PluginVersion, r.Risk, r.FairKey, r.Target, int64(r.PolicyEpoch), r.LeaseID, r.IdempotencyKey, r.SHA256Digest, r.State, r.Attempt, r.MaxAttempts, r.Bytes, r.ExpiresAt, r.CreatedAt, r.UpdatedAt, r.LastError, r.Summary, r.LeaseOwner, nullTime(r.LeaseExpiresAt))
	if err != nil {
		return diagnostics.Record{}, fmt.Errorf("%w: insert: %v", ErrInvalidStore, err)
	}
	if err = tx.Commit(); err != nil {
		return diagnostics.Record{}, err
	}
	return r, nil
}

func recordFingerprint(r diagnostics.Record) string {
	b, _ := json.Marshal(struct {
		TenantID, PluginID, PluginVersion, Risk, FairKey, Target, LeaseID, SHA256Digest string
		PolicyEpoch                                                                     uint64
		Bytes                                                                           int64
	}{r.TenantID, r.PluginID, r.PluginVersion, r.Risk, r.FairKey, r.Target, r.LeaseID, r.SHA256Digest, r.PolicyEpoch, r.Bytes})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

const selectMetadata = `SELECT upload_id,tenant_id,plugin_id,plugin_version,risk,fair_key,target,policy_epoch,lease_id,idempotency_key,sha256_digest,state,attempt,max_attempts,bytes,expires_at,created_at,updated_at,last_error,summary,lease_owner,lease_expires_at FROM cheesewaf_diagnostic_metadata`

func (s *Store) Get(ctx context.Context, id string) (diagnostics.Record, error) {
	if s == nil || s.db == nil || ctx == nil {
		return diagnostics.Record{}, ErrInvalidStore
	}
	if !validMetadataIdentifier(id) {
		return diagnostics.Record{}, ErrInvalidRecord
	}
	var r diagnostics.Record
	if err := scanRecord(s.db.QueryRowContext(ctx, selectMetadata+` WHERE upload_id=$1`, id), &r); err != nil {
		return diagnostics.Record{}, err
	}
	return r, nil
}
func scanRecord(row interface{ Scan(...any) error }, r *diagnostics.Record) error {
	var epoch int64
	var state string
	var leaseExp sql.NullTime
	err := row.Scan(&r.UploadID, &r.TenantID, &r.PluginID, &r.PluginVersion, &r.Risk, &r.FairKey, &r.Target, &epoch, &r.LeaseID, &r.IdempotencyKey, &r.SHA256Digest, &state, &r.Attempt, &r.MaxAttempts, &r.Bytes, &r.ExpiresAt, &r.CreatedAt, &r.UpdatedAt, &r.LastError, &r.Summary, &r.LeaseOwner, &leaseExp)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: scan: %v", ErrInvalidStore, err)
	}
	r.PolicyEpoch = uint64(epoch)
	r.State = diagnostics.State(state)
	if leaseExp.Valid {
		r.LeaseExpiresAt = leaseExp.Time
	}
	return nil
}
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func (s *Store) Claim(ctx context.Context, worker string, lease time.Duration) (*diagnostics.Record, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if !validMetadataIdentifier(worker) || lease <= 0 {
		return nil, ErrInvalidRecord
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var r diagnostics.Record
	err = scanRecord(tx.QueryRowContext(ctx, selectMetadata+` WHERE state='queued' AND expires_at>now() ORDER BY expires_at,tenant_id,plugin_id,risk,fair_key FOR UPDATE SKIP LOCKED LIMIT 1`), &r)
	if errors.Is(err, ErrNotFound) {
		_ = tx.Commit()
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	expires := time.Now().UTC().Add(lease)
	result, err := tx.ExecContext(ctx, `UPDATE cheesewaf_diagnostic_metadata SET state='uploading',attempt=attempt+1,lease_owner=$2,lease_expires_at=$3,updated_at=now() WHERE upload_id=$1`, r.UploadID, worker, expires)
	if err != nil {
		return nil, err
	}
	if err := requireOneRow(result); err != nil {
		return nil, err
	}
	r.State = diagnostics.StateUploading
	r.Attempt++
	r.LeaseOwner = worker
	r.LeaseExpiresAt = expires
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &r, nil
}
func (s *Store) Retry(ctx context.Context, id, reason string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if !validMetadataIdentifier(id) {
		return ErrInvalidRecord
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	var attempt, maxAttempts int
	if err = tx.QueryRowContext(ctx, `SELECT state,attempt,max_attempts FROM cheesewaf_diagnostic_metadata WHERE upload_id=$1 FOR UPDATE`, id).Scan(&state, &attempt, &maxAttempts); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if state != string(diagnostics.StateUploading) && state != string(diagnostics.StateRetrying) {
		return ErrStateConflict
	}
	if attempt >= maxAttempts {
		return diagnostics.ErrAttemptsExceeded
	}
	result, err := tx.ExecContext(ctx, `UPDATE cheesewaf_diagnostic_metadata SET state='queued',last_error=$2,lease_owner='',lease_expires_at=NULL,updated_at=now() WHERE upload_id=$1`, id, retryReasonCode(reason))
	if err != nil {
		return err
	}
	if err := requireOneRow(result); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Cancel(ctx context.Context, id, reason string) error {
	return s.transitionToCanceled(ctx, id, reason)
}
func (s *Store) transitionToCanceled(ctx context.Context, id, reason string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if !validMetadataIdentifier(id) {
		return ErrInvalidRecord
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM cheesewaf_diagnostic_metadata WHERE upload_id=$1 FOR UPDATE`, id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if state == string(diagnostics.StateCompleted) || state == string(diagnostics.StateFailed) || state == string(diagnostics.StateExpired) || state == string(diagnostics.StateCanceled) {
		return ErrStateConflict
	}
	persistedReason := cancelReasonCode(reason)
	result, err := tx.ExecContext(ctx, `UPDATE cheesewaf_diagnostic_metadata SET state=$2,last_error=$3,lease_owner='',lease_expires_at=NULL,updated_at=now() WHERE upload_id=$1`, id, diagnostics.StateCanceled, persistedReason)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: cancel update result: %v", ErrInvalidStore, err)
	}
	if rows != 1 {
		return ErrStateConflict
	}
	return tx.Commit()
}

func validMetadataIdentifier(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func retryReasonCode(reason string) string {
	return reasonCode("retry", reason)
}

func cancelReasonCode(reason string) string {
	return reasonCode("cancel", reason)
}

func reasonCode(operation, reason string) string {
	classification := classifyReason(reason)
	code := operation + ".reason." + classification
	if len(code) > maxReasonCodeLength {
		return "diagnostic.reason.invalid"
	}
	return code
}

func classifyReason(reason string) string {
	if !utf8.ValidString(reason) || containsReasonControl(reason) {
		return "invalid"
	}
	if containsSensitiveReasonMarker(reason) {
		return "sensitive"
	}
	if len(reason) > maxReasonInputLength {
		return "truncated"
	}
	return "provided"
}

func containsSensitiveReasonMarker(reason string) bool {
	if len(reason) > maxReasonInputLength {
		reason = reason[:maxReasonInputLength]
	}
	lower := strings.ToLower(reason)
	for _, marker := range sensitiveReasonMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsReasonControl(reason string) bool {
	for _, r := range reason {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

func (s *Store) AppendOutbox(ctx context.Context, o diagnostics.Outbox) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := validateOutbox(o); err != nil {
		return err
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}
	if o.AvailableAt.IsZero() {
		o.AvailableAt = o.CreatedAt
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO cheesewaf_diagnostic_outbox(event_id,upload_id,kind,state,attempt,available_at,created_at,delivered_at,lease_owner) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(event_id) DO NOTHING`, o.EventID, o.UploadID, o.Kind, o.State, o.Attempt, o.AvailableAt, o.CreatedAt, nullTime(o.DeliveredAt), o.LeaseOwner)
	return err
}
func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]diagnostics.Outbox, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,upload_id,kind,state,attempt,available_at,created_at,delivered_at,lease_owner FROM cheesewaf_diagnostic_outbox WHERE state='pending' AND available_at<=now() ORDER BY available_at,event_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []diagnostics.Outbox
	for rows.Next() {
		var o diagnostics.Outbox
		var d sql.NullTime
		if err := rows.Scan(&o.EventID, &o.UploadID, &o.Kind, &o.State, &o.Attempt, &o.AvailableAt, &o.CreatedAt, &d, &o.LeaseOwner); err != nil {
			return nil, err
		}
		if d.Valid {
			o.DeliveredAt = d.Time
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// MarkOutboxDelivered records delivery state without touching upload metadata.
func (s *Store) MarkOutboxDelivered(ctx context.Context, eventID, worker string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := validateOutboxDelivery(eventID, worker); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE cheesewaf_diagnostic_outbox SET state='delivered',delivered_at=now(),lease_owner=$2,attempt=attempt+1 WHERE event_id=$1 AND state<>'delivered'`, eventID, worker)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cheesewaf_diagnostic_outbox WHERE event_id=$1)`, eventID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
	}
	return nil
}

func validateOutbox(o diagnostics.Outbox) error {
	if !validMetadataIdentifier(o.EventID) || !validMetadataIdentifier(o.UploadID) || !validMetadataIdentifier(o.Kind) || o.State == "" || !validMetadataIdentifier(o.State) || (o.LeaseOwner != "" && !validMetadataIdentifier(o.LeaseOwner)) {
		return ErrInvalidRecord
	}
	return nil
}

func validateOutboxDelivery(eventID, worker string) error {
	if !validMetadataIdentifier(eventID) || !validMetadataIdentifier(worker) {
		return ErrInvalidRecord
	}
	return nil
}

func requireOneRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%w: update result: %v", ErrInvalidStore, err)
	}
	if rows != 1 {
		return ErrStateConflict
	}
	return nil
}
