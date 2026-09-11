// Package postgres provides the durable token persistence boundary.
// It stores metadata and a SHA-256 digest only; state and append-only audit
// event are committed in one transaction.
package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	ErrInvalidStore  = errors.New("invalid token PostgreSQL store")
	ErrTokenNotFound = tokens.ErrTokenNotFound
	ErrStaleVersion  = errors.New("token persistence stale version")
	ErrLeaseConflict = errors.New("token persistence lease conflict")
)

type Store struct{ db *sql.DB }

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
		return nil, fmt.Errorf("%w: open: %w", ErrInvalidStore, err)
	}
	s, err := New(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ping: %w", ErrInvalidStore, err)
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
		return fmt.Errorf("%w: begin migration: %w", ErrInvalidStore, err)
	}
	defer func() { _ = tx.Rollback() }()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cheesewaf_token_state (
			tenant_id TEXT NOT NULL, token_id TEXT NOT NULL, owner TEXT NOT NULL,
			permissions JSONB NOT NULL, resources JSONB NOT NULL, scopes JSONB NOT NULL,
			note TEXT NOT NULL DEFAULT '', policy_epoch BIGINT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ,
			never_expire BOOLEAN NOT NULL, disabled BOOLEAN NOT NULL, revoked BOOLEAN NOT NULL,
			last_activity_at TIMESTAMPTZ NOT NULL,
			secret_digest TEXT NOT NULL CHECK (secret_digest ~ '^[0-9a-f]{64}$'),
			lease_id TEXT NOT NULL, version BIGINT NOT NULL,
			PRIMARY KEY (tenant_id, token_id)
		)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_token_events (
			tenant_id TEXT NOT NULL, token_id TEXT NOT NULL, sequence BIGINT NOT NULL,
			event_type TEXT NOT NULL, event_at TIMESTAMPTZ NOT NULL, actor TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '', notification BOOLEAN NOT NULL,
			PRIMARY KEY (tenant_id, token_id, sequence)
		)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_token_idempotency (
			tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, token_id TEXT NOT NULL,
			fingerprint TEXT NOT NULL, recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, idempotency_key)
		)`,
		`ALTER TABLE cheesewaf_token_state ADD COLUMN IF NOT EXISTS never_expire BOOLEAN NOT NULL DEFAULT FALSE`,
		`CREATE INDEX IF NOT EXISTS cheesewaf_token_events_order_idx ON cheesewaf_token_events (tenant_id, token_id, sequence)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%w: migration: %w", ErrInvalidStore, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit migration: %w", ErrInvalidStore, err)
	}
	return nil
}

func (s *Store) Apply(ctx context.Context, mutation tokens.Mutation) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := validate(mutation); err != nil {
		return err
	}
	fingerprint := mutationFingerprint(mutation)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin apply: %w", ErrInvalidStore, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(mutation.TenantID, mutation.Token.ID)); err != nil {
		return fmt.Errorf("%w: lock token: %w", ErrInvalidStore, err)
	}
	var prior string
	err = tx.QueryRowContext(ctx, `SELECT fingerprint FROM cheesewaf_token_idempotency WHERE tenant_id=$1 AND idempotency_key=$2`, mutation.TenantID, mutation.IdempotencyKey).Scan(&prior)
	if err == nil {
		if prior != fingerprint {
			return tokens.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: idempotent commit: %w", ErrInvalidStore, err)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: idempotency lookup: %w", ErrInvalidStore, err)
	}
	var current tokens.PersistedToken
	err = loadTx(ctx, tx, mutation.TenantID, mutation.Token.ID, &current)
	if errors.Is(err, ErrTokenNotFound) {
		if mutation.ExpectedVersion != 0 || mutation.Token.Version != 1 || mutation.DeleteToken {
			return ErrStaleVersion
		}
	} else if err != nil {
		return err
	} else {
		if current.LeaseID != mutation.LeaseID {
			return ErrLeaseConflict
		}
		if mutation.ExpectedVersion != current.Version || mutation.Token.Version != current.Version+1 {
			return ErrStaleVersion
		}
	}
	var last uint64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0) FROM cheesewaf_token_events WHERE tenant_id=$1 AND token_id=$2`, mutation.TenantID, mutation.Token.ID).Scan(&last); err != nil {
		return fmt.Errorf("%w: event sequence: %w", ErrInvalidStore, err)
	}
	if mutation.Event.Sequence != last+1 {
		return ErrStaleVersion
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_token_events (tenant_id,token_id,sequence,event_type,event_at,actor,reason,notification) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, mutation.TenantID, mutation.Token.ID, mutation.Event.Sequence, mutation.Event.Type, mutation.Event.At, mutation.Event.Actor, mutation.Event.Reason, mutation.Event.Notification); err != nil {
		return fmt.Errorf("%w: append event: %w", ErrInvalidStore, err)
	}
	if mutation.DeleteToken {
		if _, err := tx.ExecContext(ctx, `DELETE FROM cheesewaf_token_state WHERE tenant_id=$1 AND token_id=$2`, mutation.TenantID, mutation.Token.ID); err != nil {
			return fmt.Errorf("%w: delete state: %w", ErrInvalidStore, err)
		}
	} else if err := upsertTx(ctx, tx, mutation.TenantID, mutation.Token); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_token_idempotency (tenant_id,idempotency_key,token_id,fingerprint) VALUES ($1,$2,$3,$4)`, mutation.TenantID, mutation.IdempotencyKey, mutation.Token.ID, fingerprint); err != nil {
		return fmt.Errorf("%w: idempotency record: %w", ErrInvalidStore, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: apply commit: %w", ErrInvalidStore, err)
	}
	return nil
}

func (s *Store) Load(ctx context.Context, tenantID, tokenID string) (tokens.PersistedToken, error) {
	if s == nil || s.db == nil || ctx == nil {
		return tokens.PersistedToken{}, ErrInvalidStore
	}
	if !strictIdentity(tenantID) || !strictIdentity(tokenID) {
		return tokens.PersistedToken{}, tokens.ErrInvalidPersistence
	}
	var out tokens.PersistedToken
	err := loadRow(s.db.QueryRowContext(ctx, `SELECT owner,permissions,resources,scopes,note,policy_epoch,created_at,expires_at,never_expire,disabled,revoked,last_activity_at,secret_digest,lease_id,version FROM cheesewaf_token_state WHERE tenant_id=$1 AND token_id=$2`, tenantID, tokenID), &out)
	if err != nil {
		return tokens.PersistedToken{}, err
	}
	out.ID = tokenID
	return out, nil
}

func (s *Store) List(ctx context.Context, tenantID string) ([]tokens.PersistedToken, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if !strictIdentity(tenantID) {
		return nil, tokens.ErrInvalidPersistence
	}
	rows, err := s.db.QueryContext(ctx, `SELECT token_id,owner,permissions,resources,scopes,note,policy_epoch,created_at,expires_at,never_expire,disabled,revoked,last_activity_at,secret_digest,lease_id,version FROM cheesewaf_token_state WHERE tenant_id=$1 ORDER BY token_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: list: %w", ErrInvalidStore, err)
	}
	defer rows.Close()
	out := make([]tokens.PersistedToken, 0)
	for rows.Next() {
		var item tokens.PersistedToken
		var id string
		if err := scanToken(rows, &id, &item); err != nil {
			return nil, err
		}
		item.ID = id
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: list rows: %w", ErrInvalidStore, err)
	}
	return out, nil
}

func (s *Store) Events(ctx context.Context, tenantID, tokenID string) ([]tokens.Event, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if !strictIdentity(tenantID) || !strictIdentity(tokenID) {
		return nil, tokens.ErrInvalidPersistence
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,event_type,event_at,actor,reason,notification FROM cheesewaf_token_events WHERE tenant_id=$1 AND token_id=$2 ORDER BY sequence`, tenantID, tokenID)
	if err != nil {
		return nil, fmt.Errorf("%w: events: %w", ErrInvalidStore, err)
	}
	defer rows.Close()
	out := make([]tokens.Event, 0)
	for rows.Next() {
		var e tokens.Event
		var typ string
		if err := rows.Scan(&e.Sequence, &typ, &e.At, &e.Actor, &e.Reason, &e.Notification); err != nil {
			return nil, fmt.Errorf("%w: scan event: %w", ErrInvalidStore, err)
		}
		e.Type = tokens.EventType(typ)
		e.TokenID = tokenID
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: event rows: %w", ErrInvalidStore, err)
	}
	return out, nil
}

func validate(m tokens.Mutation) error {
	if !strictIdentity(m.TenantID) || !strictIdentity(m.Token.ID) || !strictIdentity(m.Token.Owner) || !strictIdentity(m.LeaseID) || !strictIdentity(m.IdempotencyKey) {
		return tokens.ErrInvalidPersistence
	}
	if (m.Event.Actor != "" && !strictIdentity(m.Event.Actor)) || !validIdentityList(m.Token.Permissions) || !validIdentityList(m.Token.Resources) || !validIdentityList(m.Token.Scopes) {
		return tokens.ErrInvalidPersistence
	}
	if len(m.Token.SecretDigest) != 64 || m.Token.SecretDigest != strings.ToLower(m.Token.SecretDigest) {
		return tokens.ErrInvalidPersistence
	}
	for _, r := range m.Token.SecretDigest {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return tokens.ErrInvalidPersistence
		}
	}
	if m.Token.PolicyEpoch == 0 || m.Token.PolicyEpoch > math.MaxInt64 || m.Token.Version > math.MaxInt64 || m.Event.Sequence > math.MaxInt64 || m.Token.CreatedAt.IsZero() || m.Token.LastActivityAt.IsZero() || m.Token.LastActivityAt.Before(m.Token.CreatedAt) || (!m.Token.NeverExpire && m.Token.ExpiresAt.IsZero()) {
		return tokens.ErrInvalidPersistence
	}
	if m.Token.NeverExpire && !m.Token.ExpiresAt.IsZero() {
		return tokens.ErrInvalidPersistence
	}
	if !m.Token.ExpiresAt.IsZero() && !m.Token.ExpiresAt.After(m.Token.CreatedAt) {
		return tokens.ErrInvalidPersistence
	}
	if !m.Token.ExpiresAt.IsZero() && m.Token.ExpiresAt.Sub(m.Token.CreatedAt) > tokens.MaxTTL {
		return tokens.ErrInvalidPersistence
	}
	if m.Event.TokenID != m.Token.ID || m.Event.Sequence == 0 || m.Event.At.IsZero() || strings.TrimSpace(string(m.Event.Type)) == "" || m.Token.Version == 0 {
		return tokens.ErrInvalidPersistence
	}
	return nil
}

func mutationFingerprint(m tokens.Mutation) string {
	payload, _ := json.Marshal(struct {
		Tenant, Lease, Key string
		Expected           uint64
		Delete             bool
		Token              tokens.PersistedToken
		Event              tokens.Event
	}{m.TenantID, m.LeaseID, m.IdempotencyKey, m.ExpectedVersion, m.DeleteToken, m.Token, m.Event})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
func lockKey(tenant, tokenID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(tenant + "\x00" + tokenID))
	return int64(h.Sum64() & 0x7fffffffffffffff)
}

type rowScanner interface{ Scan(...any) error }

func loadRow(row rowScanner, out *tokens.PersistedToken) error {
	var perms, res, scopes []byte
	var expires sql.NullTime
	var epoch, version int64
	if err := row.Scan(&out.Owner, &perms, &res, &scopes, &out.Note, &epoch, &out.CreatedAt, &expires, &out.NeverExpire, &out.Disabled, &out.Revoked, &out.LastActivityAt, &out.SecretDigest, &out.LeaseID, &version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenNotFound
		}
		return fmt.Errorf("%w: load: %w", ErrInvalidStore, err)
	}
	if err := validateLoaded(epoch, version, out.SecretDigest); err != nil {
		return err
	}
	out.PolicyEpoch = uint64(epoch)
	out.Version = uint64(version)
	if expires.Valid {
		out.ExpiresAt = expires.Time
	}
	if json.Unmarshal(perms, &out.Permissions) != nil || json.Unmarshal(res, &out.Resources) != nil || json.Unmarshal(scopes, &out.Scopes) != nil {
		return fmt.Errorf("%w: decode scope", ErrInvalidStore)
	}
	return nil
}

func validateLoaded(epoch, version int64, digest string) error {
	if epoch <= 0 || version <= 0 || len(digest) != 64 || digest != strings.ToLower(digest) {
		return tokens.ErrInvalidPersistence
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return tokens.ErrInvalidPersistence
	}
	return nil
}

func strictIdentity(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validIdentityList(values []string) bool {
	for _, value := range values {
		if !strictIdentity(value) {
			return false
		}
	}
	return true
}
func scanToken(rows rowScanner, id *string, out *tokens.PersistedToken) error {
	var perms, res, scopes []byte
	var expires sql.NullTime
	var epoch, version int64
	if err := rows.Scan(id, &out.Owner, &perms, &res, &scopes, &out.Note, &epoch, &out.CreatedAt, &expires, &out.NeverExpire, &out.Disabled, &out.Revoked, &out.LastActivityAt, &out.SecretDigest, &out.LeaseID, &version); err != nil {
		return fmt.Errorf("%w: scan token: %w", ErrInvalidStore, err)
	}
	if err := validateLoaded(epoch, version, out.SecretDigest); err != nil {
		return err
	}
	out.PolicyEpoch = uint64(epoch)
	out.Version = uint64(version)
	if expires.Valid {
		out.ExpiresAt = expires.Time
	}
	if json.Unmarshal(perms, &out.Permissions) != nil || json.Unmarshal(res, &out.Resources) != nil || json.Unmarshal(scopes, &out.Scopes) != nil {
		return fmt.Errorf("%w: decode scope", ErrInvalidStore)
	}
	return nil
}
func loadTx(ctx context.Context, tx *sql.Tx, tenantID, tokenID string, out *tokens.PersistedToken) error {
	out.ID = tokenID
	return loadRow(tx.QueryRowContext(ctx, `SELECT owner,permissions,resources,scopes,note,policy_epoch,created_at,expires_at,never_expire,disabled,revoked,last_activity_at,secret_digest,lease_id,version FROM cheesewaf_token_state WHERE tenant_id=$1 AND token_id=$2 FOR UPDATE`, tenantID, tokenID), out)
}
func upsertTx(ctx context.Context, tx *sql.Tx, tenantID string, t tokens.PersistedToken) error {
	perms, _ := json.Marshal(t.Permissions)
	res, _ := json.Marshal(t.Resources)
	scopes, _ := json.Marshal(t.Scopes)
	var expires any
	if !t.ExpiresAt.IsZero() {
		expires = t.ExpiresAt
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_token_state (tenant_id,token_id,owner,permissions,resources,scopes,note,policy_epoch,created_at,expires_at,never_expire,disabled,revoked,last_activity_at,secret_digest,lease_id,version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT (tenant_id,token_id) DO UPDATE SET owner=EXCLUDED.owner,permissions=EXCLUDED.permissions,resources=EXCLUDED.resources,scopes=EXCLUDED.scopes,note=EXCLUDED.note,policy_epoch=EXCLUDED.policy_epoch,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at,never_expire=EXCLUDED.never_expire,disabled=EXCLUDED.disabled,revoked=EXCLUDED.revoked,last_activity_at=EXCLUDED.last_activity_at,secret_digest=EXCLUDED.secret_digest,lease_id=EXCLUDED.lease_id,version=EXCLUDED.version`, tenantID, t.ID, t.Owner, perms, res, scopes, t.Note, int64(t.PolicyEpoch), t.CreatedAt, expires, t.NeverExpire, t.Disabled, t.Revoked, t.LastActivityAt, t.SecretDigest, t.LeaseID, int64(t.Version))
	if err != nil {
		return fmt.Errorf("%w: upsert state: %w", ErrInvalidStore, err)
	}
	return nil
}
