// Package postgres provides the durable CRP activation authorization adapter.
//
// The adapter deliberately uses the approval ledger as its authority source.
// A transport claim is metadata only; Authorize succeeds only when the
// referenced approval record is approved and all binding fields match.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	ErrInvalidStore        = errors.New("invalid CRP activation PostgreSQL store")
	ErrApprovalUnavailable = errors.New("CRP approval record is unavailable")
	ErrAuditConflict       = errors.New("CRP authorization audit EventID conflicts")
)

type Store struct {
	db          *sql.DB
	clock       func() time.Time
	fenceSource FenceSource
}

// FenceSource binds CRP grants to the live native-raft control-plane fence.
// Production must not mint an in-process random token and call it a fence.
type FenceSource interface {
	CurrentFence(context.Context, activation.AuthorizationRequest) (activation.Fence, error)
	ValidateFence(context.Context, activation.Authorization, activation.Fence) error
}

var _ activation.DurableAuthorizationState = (*Store)(nil)
var _ activation.IdempotentAuthorizationAudit = (*Store)(nil)

// Provider is the durable control-plane authority backed by Store. It is a
// separate type because AuthorizationState and AuthorizationProvider both
// have a method named Consume with different signatures.
type Provider struct{ store *Store }

var _ activation.DurableAuthorizationProvider = (*Provider)(nil)
var _ activation.AuthorizationStateCoalescingProvider = (*Provider)(nil)

func NewProvider(store *Store) (*Provider, error) {
	if store == nil || store.db == nil {
		return nil, ErrInvalidStore
	}
	return &Provider{store: store}, nil
}

func (s *Store) Provider() (*Provider, error) { return NewProvider(s) }

func (p *Provider) Durable() bool { return p != nil && p.store != nil && p.store.Durable() }

// LiveFenceBound proves that this provider was constructed with a live
// native-raft fence source. ProductionContract requires this capability;
// New remains intentionally usable for storage-only tests.
func (p *Provider) LiveFenceBound() bool {
	return p != nil && p.store != nil && !isNilFenceSource(p.store.fenceSource)
}

func (p *Provider) Authorize(ctx context.Context, identity activation.TransportIdentity, request activation.AuthorizationRequest) (activation.Authorization, error) {
	if p == nil || p.store == nil {
		return activation.Authorization{}, ErrInvalidStore
	}
	return p.store.authorize(ctx, identity, request)
}

func (p *Provider) Validate(ctx context.Context, identity activation.TransportIdentity, authorization activation.Authorization) error {
	if p == nil || p.store == nil {
		return ErrInvalidStore
	}
	return p.store.validate(ctx, identity, authorization)
}

func (p *Provider) Consume(ctx context.Context, identity activation.TransportIdentity, authorization activation.Authorization) error {
	if p == nil || p.store == nil {
		return ErrInvalidStore
	}
	if authorization.Request.Identity != identity {
		return activation.ErrAuthorizationBinding
	}
	return p.store.Consume(ctx, authorization)
}

// UsesAuthorizationState identifies the exact Store shared by the handler and
// this provider. Pointer identity is intentional: two Store values may target
// the same database, but only the same instance is an explicit composition
// guarantee that the handler's state transition already performed this
// provider's durable consume operation.
func (p *Provider) UsesAuthorizationState(state activation.AuthorizationState) bool {
	store, ok := state.(*Store)
	return ok && p != nil && p.store != nil && store == p.store
}

// ConsumeAfterState performs the provider-side binding check after the shared
// Store has atomically consumed the authorization. It deliberately does not
// call Store.Consume again; the handler-owned state transition is the single
// replay-protected write.
func (p *Provider) ConsumeAfterState(_ context.Context, identity activation.TransportIdentity, authorization activation.Authorization) error {
	if p == nil || p.store == nil {
		return ErrInvalidStore
	}
	if authorization.Request.Identity != identity {
		return activation.ErrAuthorizationBinding
	}
	return nil
}

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, ErrInvalidStore
	}
	return &Store{db: db, clock: time.Now}, nil
}

// NewWithFenceSource is the production constructor. New remains available for
// storage-only adapter tests; the serve composition root always supplies a
// live fence source through this constructor.
func NewWithFenceSource(db *sql.DB, source FenceSource) (*Store, error) {
	if isNilFenceSource(source) {
		return nil, ErrInvalidStore
	}
	store, err := New(db)
	if err != nil {
		return nil, err
	}
	store.fenceSource = source
	return store, nil
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
	s, err := New(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ping: %v", ErrInvalidStore, err)
	}
	return s, nil
}

// OpenWithFenceSource is the fail-closed production opener used by serve.
func OpenWithFenceSource(ctx context.Context, dsn string, source FenceSource) (*Store, error) {
	if isNilFenceSource(source) {
		return nil, ErrInvalidStore
	}
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
	s, err := NewWithFenceSource(db, source)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
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

func (s *Store) Durable() bool { return s != nil && s.db != nil }

// Migrate creates only the CRP-specific tables. Approval tables are owned by
// internal/approval/postgres and are intentionally not recreated here.
func (s *Store) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cheesewaf_crp_authorizations (
			id TEXT PRIMARY KEY,
			authorization_json JSONB NOT NULL,
			binding_digest TEXT NOT NULL,
			approval_id TEXT NOT NULL,
			action TEXT NOT NULL,
			target_key TEXT NOT NULL,
			target_revision BIGINT NOT NULL,
			expected_revision BIGINT NOT NULL,
			scope TEXT NOT NULL,
			policy_epoch BIGINT NOT NULL,
			nonce TEXT NOT NULL,
			session_id TEXT NOT NULL,
			ttl_nanos BIGINT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			consumed_at TIMESTAMPTZ,
			provider_consumed_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE INDEX IF NOT EXISTS cheesewaf_crp_authorizations_expiry_idx ON cheesewaf_crp_authorizations (expires_at)`,
		`CREATE INDEX IF NOT EXISTS cheesewaf_crp_authorizations_approval_idx ON cheesewaf_crp_authorizations (approval_id)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_crp_authorization_audit (
			event_id TEXT PRIMARY KEY,
			event_json JSONB NOT NULL,
			payload_digest TEXT NOT NULL,
			recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%w: migration: %v", ErrInvalidStore, err)
		}
	}
	return tx.Commit()
}

func (s *Store) Put(ctx context.Context, authorization activation.Authorization) error {
	if err := s.valid(ctx); err != nil {
		return err
	}
	if authorization.ID == "" {
		return activation.ErrAuthorizationBinding
	}
	b, digest, err := authorizationPayload(authorization)
	if err != nil {
		return err
	}
	args := authorizationColumns(authorization, b, digest)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var priorDigest string
	var consumed sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT binding_digest,consumed_at FROM cheesewaf_crp_authorizations WHERE id=$1 FOR UPDATE`, authorization.ID).Scan(&priorDigest, &consumed)
	if err == nil {
		if consumed.Valid {
			return activation.ErrAuthorizationReplay
		}
		if priorDigest == digest {
			return tx.Commit()
		}
		return activation.ErrAuthorizationBinding
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO cheesewaf_crp_authorizations
		(id,authorization_json,binding_digest,approval_id,action,target_key,target_revision,expected_revision,scope,policy_epoch,nonce,session_id,ttl_nanos,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, args...)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Get(ctx context.Context, id string) (activation.Authorization, error) {
	if err := s.valid(ctx); err != nil {
		return activation.Authorization{}, err
	}
	if id == "" {
		return activation.Authorization{}, activation.ErrAuthorizationNotFound
	}
	var payload []byte
	var digest string
	var expires time.Time
	var consumed sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT authorization_json,binding_digest,expires_at,consumed_at FROM cheesewaf_crp_authorizations WHERE id=$1`, id).Scan(&payload, &digest, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return activation.Authorization{}, activation.ErrAuthorizationNotFound
	}
	if err != nil {
		return activation.Authorization{}, err
	}
	if consumed.Valid {
		return activation.Authorization{}, activation.ErrAuthorizationReplay
	}
	if !expires.After(s.now()) {
		return activation.Authorization{}, activation.ErrAuthorizationNotFound
	}
	var authorization activation.Authorization
	if err := json.Unmarshal(payload, &authorization); err != nil {
		return activation.Authorization{}, fmt.Errorf("%w: decode authorization: %v", ErrInvalidStore, err)
	}
	if _, actual, err := authorizationPayload(authorization); err != nil || actual != digest {
		return activation.Authorization{}, ErrInvalidStore
	}
	return authorization, nil
}

func (s *Store) Consume(ctx context.Context, authorization activation.Authorization) error {
	if err := s.valid(ctx); err != nil {
		return err
	}
	_, digest, err := authorizationPayload(authorization)
	if err != nil {
		return err
	}
	// Consensus is intentionally checked before the PostgreSQL transaction.
	// Calling native-raft while a FOR UPDATE row lock is held creates an
	// avoidable cross-system lock dependency. A second check after commit makes
	// a fence transition during the short transaction fail closed to the caller.
	if err := s.validateLiveFence(ctx, authorization); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var priorDigest string
	var consumed sql.NullTime
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT binding_digest,consumed_at,expires_at FROM cheesewaf_crp_authorizations WHERE id=$1 FOR UPDATE`, authorization.ID).Scan(&priorDigest, &consumed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return activation.ErrAuthorizationNotFound
	}
	if err != nil {
		return err
	}
	if priorDigest != digest {
		return activation.ErrAuthorizationBinding
	}
	if consumed.Valid {
		return activation.ErrAuthorizationReplay
	}
	if !expires.After(s.now()) {
		return activation.ErrAuthorizationNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE cheesewaf_crp_authorizations SET consumed_at=$2,provider_consumed_at=COALESCE(provider_consumed_at,$2) WHERE id=$1`, authorization.ID, s.now()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// A perfectly atomic operation spanning PostgreSQL and native-raft is not
	// available through FenceSource. This recheck closes the observable window:
	// a turnover during the locked SQL section consumes the one-shot grant but
	// never returns Consume success, so the caller cannot proceed on it.
	return s.validateLiveFence(ctx, authorization)
}

// Authorize verifies the approval ledger and creates a durable authorization
// snapshot. The approval row and epoch are locked in the same transaction as
// the authorization insert, so an epoch/revocation race cannot mint a grant.
func (s *Store) authorize(ctx context.Context, identity activation.TransportIdentity, request activation.AuthorizationRequest) (activation.Authorization, error) {
	if err := s.valid(ctx); err != nil {
		return activation.Authorization{}, err
	}
	if err := validateRequest(identity, request); err != nil {
		return activation.Authorization{}, err
	}
	now := s.now()
	// Fetch consensus before taking approval/epoch locks. A turnover after this
	// snapshot only leaves a persisted but immediately stale authorization; the
	// post-commit validation below prevents it from being returned as usable.
	var liveFence activation.Fence
	if s.fenceSource != nil {
		var err error
		liveFence, err = s.currentLiveFence(ctx, request)
		if err != nil {
			return activation.Authorization{}, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return activation.Authorization{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var recordJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT record_json FROM cheesewaf_approvals WHERE request_id=$1 FOR UPDATE`, request.ApprovalClaim.ApprovalID).Scan(&recordJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return activation.Authorization{}, ErrApprovalUnavailable
	}
	if err != nil {
		return activation.Authorization{}, err
	}
	var record approval.Record
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return activation.Authorization{}, fmt.Errorf("%w: decode approval: %v", ErrApprovalUnavailable, err)
	}
	if err := validateApproval(record, request); err != nil {
		return activation.Authorization{}, err
	}
	var epoch uint64
	if err := tx.QueryRowContext(ctx, `SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1 FOR UPDATE`).Scan(&epoch); err != nil {
		return activation.Authorization{}, ErrApprovalUnavailable
	}
	if epoch != request.ApprovalClaim.PolicyEpoch {
		return activation.Authorization{}, activation.ErrAuthorizationDenied
	}
	expires := now.Add(request.ApprovalClaim.TTL)
	if request.ApprovalClaim.ExpiresAt.Before(expires) {
		expires = request.ApprovalClaim.ExpiresAt
	}
	if !expires.After(now) {
		return activation.Authorization{}, activation.ErrAuthorizationDenied
	}
	var fence activation.Fence
	if !isNilFenceSource(s.fenceSource) {
		fence = liveFence
		if fence.ExpiresAt.Before(expires) {
			expires = fence.ExpiresAt
		}
		if !expires.After(now) {
			return activation.Authorization{}, activation.ErrAuthorizationDenied
		}
		fence.ExpiresAt = expires
	} else {
		// New is limited to storage-only tests. Production construction must use
		// NewWithFenceSource and is rejected by ProductionContract otherwise.
		fence = activation.Fence{ClusterID: identity.ClusterID, Token: "crp-fence-" + uuid.NewString(), Epoch: epoch, Revision: request.ExpectedRevision, ExpiresAt: expires}
	}
	authorization := activation.Authorization{
		SchemaVersion: activation.TransportSchemaVersion,
		ID:            "crp-auth-" + uuid.NewString(), Request: request, ApprovalClaim: request.ApprovalClaim,
		Fence:        fence,
		Confirmation: &activation.WireConfirmation{ID: request.ApprovalClaim.ConfirmationID, Actor: request.ApprovalClaim.Actor, Action: request.Action, PluginKey: request.Target.Key, ManifestIdentity: request.Target.ManifestIdentity, ExpectedRevision: request.ExpectedRevision, AuthorizedAt: now, ExpiresAt: expires},
		IssuedAt:     now, ExpiresAt: expires,
	}
	b, digest, err := authorizationPayload(authorization)
	if err != nil {
		return activation.Authorization{}, err
	}
	args := authorizationColumns(authorization, b, digest)
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_crp_authorizations
		(id,authorization_json,binding_digest,approval_id,action,target_key,target_revision,expected_revision,scope,policy_epoch,nonce,session_id,ttl_nanos,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO NOTHING`, args...); err != nil {
		return activation.Authorization{}, err
	}
	if err := tx.Commit(); err != nil {
		return activation.Authorization{}, err
	}
	if err := s.validateLiveFence(ctx, authorization); err != nil {
		return activation.Authorization{}, err
	}
	return authorization, nil
}

func (s *Store) validate(ctx context.Context, identity activation.TransportIdentity, authorization activation.Authorization) error {
	if err := s.valid(ctx); err != nil {
		return err
	}
	if authorization.Request.Identity != identity {
		return activation.ErrAuthorizationBinding
	}
	now := s.now()
	if !authorization.ExpiresAt.After(now) {
		return activation.ErrAuthorizationDenied
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var payload []byte
	var storedDigest string
	var expires time.Time
	var consumed sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT authorization_json,binding_digest,expires_at,consumed_at FROM cheesewaf_crp_authorizations WHERE id=$1`, authorization.ID).Scan(&payload, &storedDigest, &expires, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return activation.ErrAuthorizationNotFound
	}
	if err != nil {
		return err
	}
	if consumed.Valid {
		return activation.ErrAuthorizationReplay
	}
	if !expires.After(now) {
		return activation.ErrAuthorizationDenied
	}
	_, suppliedDigest, err := authorizationPayload(authorization)
	if err != nil || suppliedDigest != storedDigest {
		return activation.ErrAuthorizationBinding
	}
	var recordJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT record_json FROM cheesewaf_approvals WHERE request_id=$1`, authorization.Request.ApprovalClaim.ApprovalID).Scan(&recordJSON); errors.Is(err, sql.ErrNoRows) {
		return ErrApprovalUnavailable
	} else if err != nil {
		return err
	}
	var record approval.Record
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return ErrApprovalUnavailable
	}
	if err := validateApproval(record, authorization.Request); err != nil {
		return err
	}
	var epoch uint64
	if err := tx.QueryRowContext(ctx, `SELECT policy_epoch FROM cheesewaf_approval_epoch WHERE id=1`).Scan(&epoch); err != nil || epoch != authorization.Request.ApprovalClaim.PolicyEpoch {
		return activation.ErrAuthorizationDenied
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.validateLiveFence(ctx, authorization)
}

func (s *Store) currentLiveFence(ctx context.Context, request activation.AuthorizationRequest) (activation.Fence, error) {
	if s == nil || isNilFenceSource(s.fenceSource) {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	fence, err := s.fenceSource.CurrentFence(ctx, request)
	if err != nil {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	if fence.ClusterID != request.Identity.ClusterID || strings.TrimSpace(fence.Token) == "" || fence.Epoch == 0 || fence.Revision == 0 || fence.ExpiresAt.IsZero() || !fence.ExpiresAt.After(s.now()) {
		return activation.Fence{}, activation.ErrControlPlaneUnavailable
	}
	return fence, nil
}

func (s *Store) validateLiveFence(ctx context.Context, authorization activation.Authorization) error {
	if s == nil || isNilFenceSource(s.fenceSource) {
		return nil
	}
	current, err := s.currentLiveFence(ctx, authorization.Request)
	if err != nil {
		return err
	}
	return s.fenceSource.ValidateFence(ctx, authorization, current)
}

func isNilFenceSource(source FenceSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (s *Store) validateApprovalRow(ctx context.Context, request activation.AuthorizationRequest) error {
	var payload []byte
	if err := s.db.QueryRowContext(ctx, `SELECT record_json FROM cheesewaf_approvals WHERE request_id=$1`, request.ApprovalClaim.ApprovalID).Scan(&payload); errors.Is(err, sql.ErrNoRows) {
		return ErrApprovalUnavailable
	} else if err != nil {
		return err
	} else {
		var record approval.Record
		if err := json.Unmarshal(payload, &record); err != nil {
			return ErrApprovalUnavailable
		}
		return validateApproval(record, request)
	}
}

func (s *Store) Append(ctx context.Context, event activation.AuthorizationAuditEvent) error {
	if err := s.valid(ctx); err != nil {
		return err
	}
	if event.EventID == "" {
		return ErrAuditConflict
	}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	digest := approval.HashBytes(b)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var prior string
	err = tx.QueryRowContext(ctx, `SELECT payload_digest FROM cheesewaf_crp_authorization_audit WHERE event_id=$1 FOR UPDATE`, event.EventID).Scan(&prior)
	if err == nil {
		if prior == digest {
			return tx.Commit()
		}
		return ErrAuditConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_crp_authorization_audit(event_id,event_json,payload_digest) VALUES($1,$2,$3)`, event.EventID, b, digest); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Idempotent() bool { return s != nil && s.db != nil }

func (s *Store) valid(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrInvalidStore
	}
	if ctx == nil {
		return ErrInvalidStore
	}
	return ctx.Err()
}

func (s *Store) now() time.Time {
	if s == nil || s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock().UTC()
}

func authorizationPayload(a activation.Authorization) ([]byte, string, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, "", err
	}
	return b, approval.HashBytes(b), nil
}

func authorizationColumns(a activation.Authorization, b []byte, digest string) []any {
	return []any{a.ID, b, digest, a.Request.ApprovalClaim.ApprovalID, string(a.Request.Action), a.Request.Target.Key, int64(a.Request.Target.Revision), int64(a.Request.ExpectedRevision), a.Request.ApprovalClaim.Scope, int64(a.Request.ApprovalClaim.PolicyEpoch), a.Request.ApprovalClaim.Nonce, a.Request.ApprovalClaim.SessionID, int64(a.Request.ApprovalClaim.TTL), a.ExpiresAt}
}

func validateRequest(identity activation.TransportIdentity, request activation.AuthorizationRequest) error {
	if request.SchemaVersion != activation.TransportSchemaVersion || request.Identity != identity || request.RequestID == "" || request.ExpectedRevision == 0 || request.ApprovalClaim.ApprovalID == "" || request.ApprovalClaim.ConfirmationID == "" || request.ApprovalClaim.Actor == "" || request.ApprovalClaim.Nonce == "" || request.ApprovalClaim.SessionID == "" {
		return activation.ErrAuthorizationBinding
	}
	wantPermission := map[string]activation.Permission{"stage": activation.PermissionStage, "promote": activation.PermissionActivate, "rollback": activation.PermissionRollback}[string(request.Action)]
	if wantPermission == "" || request.Permission != wantPermission {
		return activation.ErrAuthorizationBinding
	}
	claim := request.ApprovalClaim
	if claim.IntentDigest != activation.ApprovalIntentDigest(request) || claim.Scope != activation.ApprovalScope(request) || claim.PolicyEpoch == 0 || claim.TTL <= 0 || claim.TTL > 5*time.Minute || claim.IssuedAt.IsZero() || claim.ExpiresAt.IsZero() || claim.ExpiresAt.Sub(claim.IssuedAt) != claim.TTL {
		return activation.ErrAuthorizationBinding
	}
	if request.Action == crp.RuntimeActionPromote && request.Target.Revision != request.ExpectedRevision {
		return activation.ErrAuthorizationBinding
	}
	if request.Action == crp.RuntimeActionRollback && request.Target.Revision >= request.ExpectedRevision {
		return activation.ErrAuthorizationBinding
	}
	return nil
}

func validateApproval(record approval.Record, request activation.AuthorizationRequest) error {
	if err := approval.ValidateRecordForAdapter(record); err != nil {
		return activation.ErrAuthorizationDenied
	}
	claim := request.ApprovalClaim
	if record.ID != claim.ApprovalID || record.Status != approval.StatusApproved || record.Commit == nil || record.Request.Scope != claim.Scope || record.Request.PolicyEpoch != claim.PolicyEpoch || record.Request.IntentDigest != claim.IntentDigest || record.Request.Nonce != claim.Nonce || record.Request.SessionID != claim.SessionID || record.Request.Actor != claim.Actor || !record.ExpiresAt.Equal(claim.ExpiresAt) {
		return activation.ErrAuthorizationDenied
	}
	commit := record.Commit
	// The approval TTL starts at submission; the claim window starts only
	// after confirmation and must retain the original expiry.
	effectiveTTL := commit.ExpiresAt.Sub(commit.IssuedAt)
	if commit.TTL != record.Request.TTL || effectiveTTL <= 0 || effectiveTTL > record.Request.TTL ||
		claim.TTL != effectiveTTL || !claim.IssuedAt.Equal(commit.IssuedAt) || !claim.ExpiresAt.Equal(commit.ExpiresAt) {
		return activation.ErrAuthorizationBinding
	}
	if record.Commit.ConfirmationID != claim.ConfirmationID || record.Commit.Scope != claim.Scope || record.Commit.PolicyEpoch != claim.PolicyEpoch || record.Commit.IntentDigest != claim.IntentDigest || record.Commit.Nonce != claim.Nonce || record.Commit.SessionID != claim.SessionID {
		return activation.ErrAuthorizationBinding
	}
	return nil
}
