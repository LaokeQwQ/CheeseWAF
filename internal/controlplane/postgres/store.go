// Package postgres provides the durable PostgreSQL adapter for the control-plane contract.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	stateTable  = "cheesewaf_controlplane_state"
	commitTable = "cheesewaf_controlplane_commits"
)

var (
	ErrInvalidStore   = errors.New("invalid control-plane PostgreSQL store")
	ErrStateNotFound  = controlplane.ErrStateNotFound
	ErrCommitConflict = errors.New("control-plane commit conflicts with an existing tuple")
	ErrStaleCommit    = errors.New("control-plane commit is stale")
	ErrSequenceGap    = errors.New("control-plane commit has a revision gap")
	ErrWritesFrozen   = errors.New("control-plane writes are frozen")
)

type Store struct{ db *sql.DB }

// Backend identifies this adapter for the production startup contract.
func (s *Store) Backend() string {
	return "postgresql"
}

// Prepare performs the idempotent control-plane schema migration required
// before a durable snapshot is loaded.
func (s *Store) Prepare(ctx context.Context) error {
	return s.Migrate(ctx)
}

// Health verifies that the PostgreSQL connection is usable before startup
// reads the control-plane snapshot.
func (s *Store) Health(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrInvalidStore
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return s.db.PingContext(ctx)
}

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
	store, err := New(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ping: %w", ErrInvalidStore, err)
	}
	return store, nil
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
		`CREATE TABLE IF NOT EXISTS cheesewaf_controlplane_state (
			cluster_id TEXT PRIMARY KEY, leader_id TEXT NOT NULL DEFAULT '', term BIGINT NOT NULL DEFAULT 0,
			epoch BIGINT NOT NULL DEFAULT 0, revision BIGINT NOT NULL DEFAULT 0, desired_version TEXT NOT NULL DEFAULT '',
			desired_digest TEXT NOT NULL DEFAULT '', desired_payload BYTEA NOT NULL DEFAULT decode('', 'hex'),
			write_frozen BOOLEAN NOT NULL DEFAULT TRUE, freeze_reason TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL, nonce_ledger JSONB NOT NULL DEFAULT '{}'::jsonb
		)`,
		`CREATE TABLE IF NOT EXISTS cheesewaf_controlplane_commits (
			cluster_id TEXT NOT NULL, epoch BIGINT NOT NULL, revision BIGINT NOT NULL, nonce TEXT NOT NULL,
			leader_id TEXT NOT NULL, term BIGINT NOT NULL, digest TEXT NOT NULL, version TEXT NOT NULL,
			payload BYTEA NOT NULL, state_json JSONB NOT NULL, committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (cluster_id, epoch, revision, nonce),
			UNIQUE (cluster_id, revision), UNIQUE (cluster_id, nonce)
		)`,
		`CREATE INDEX IF NOT EXISTS cheesewaf_controlplane_commits_order_idx ON cheesewaf_controlplane_commits (cluster_id, epoch, revision)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%w: migration statement: %w", ErrInvalidStore, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit migration: %w", ErrInvalidStore, err)
	}
	return nil
}

func (s *Store) LoadState(ctx context.Context, clusterID string) (controlplane.State, error) {
	if s == nil || s.db == nil || ctx == nil {
		return controlplane.State{}, ErrInvalidStore
	}
	if !controlplane.ValidIdentity(clusterID) {
		return controlplane.State{}, fmt.Errorf("%w: cluster ID is required", ErrInvalidStore)
	}
	var leader, version, digest, reason string
	var term, epoch, revision int64
	var payload, ledger []byte
	var frozen bool
	var updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT leader_id, term, epoch, revision, desired_version, desired_digest, desired_payload, write_frozen, freeze_reason, updated_at, nonce_ledger FROM cheesewaf_controlplane_state WHERE cluster_id = $1`, clusterID).Scan(&leader, &term, &epoch, &revision, &version, &digest, &payload, &frozen, &reason, &updated, &ledger)
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.State{}, ErrStateNotFound
	}
	if err != nil {
		return controlplane.State{}, fmt.Errorf("%w: load state: %w", ErrInvalidStore, err)
	}
	state, err := decodeState(clusterID, leader, term, epoch, revision, version, digest, payload, frozen, reason, updated, ledger)
	if err != nil {
		return controlplane.State{}, err
	}
	return state, nil
}

func (s *Store) AppendCommit(ctx context.Context, commit controlplane.Commit) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := validateCommitFields(commit); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin append: %w", ErrInvalidStore, err)
	}
	defer func() { _ = tx.Rollback() }()
	key := commit.Fence
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, clusterLockKey(key.ClusterID)); err != nil {
		return fmt.Errorf("%w: lock cluster: %w", ErrInvalidStore, err)
	}
	var oldJSON, oldLeader, oldDigest, oldVersion string
	var oldTerm int64
	var oldPayload []byte
	err = tx.QueryRowContext(ctx, `SELECT state_json::text, leader_id, term, digest, version, payload FROM cheesewaf_controlplane_commits WHERE cluster_id = $1 AND epoch = $2 AND revision = $3 AND nonce = $4`, key.ClusterID, int64(key.Epoch), int64(key.Revision), key.Nonce).Scan(&oldJSON, &oldLeader, &oldTerm, &oldDigest, &oldVersion, &oldPayload)
	if err == nil {
		var oldState controlplane.State
		if decodeErr := json.Unmarshal([]byte(oldJSON), &oldState); decodeErr != nil {
			return fmt.Errorf("%w: decode existing state: %w", ErrInvalidStore, decodeErr)
		}
		oldState.Desired.Payload = append([]byte(nil), oldPayload...)
		if oldLeader != key.LeaderID || oldTerm != int64(commit.State.Term) || oldDigest != key.Digest || oldVersion != commit.State.Desired.Version || !bytesEqual(oldPayload, commit.State.Desired.Payload) || !sameState(oldState, commit.State) {
			return ErrCommitConflict
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%w: idempotent commit: %w", ErrInvalidStore, err)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: inspect commit: %w", ErrInvalidStore, err)
	}
	var current controlplane.State
	current, err = loadStateTx(ctx, tx, key.ClusterID)
	if err != nil && !errors.Is(err, ErrStateNotFound) {
		return err
	}
	if errors.Is(err, ErrStateNotFound) {
		if commit.State.Revision != 1 {
			return ErrSequenceGap
		}
	} else {
		if err := validateTransition(current, commit); err != nil {
			return err
		}
	}
	stateForJSON := commit.State
	// BYTEA is the byte-for-byte source of truth for the payload. JSONB
	// normalizes whitespace and object representation, so do not duplicate the
	// raw payload in state_json (otherwise an exact retry can appear different).
	stateForJSON.Desired.Payload = nil
	stateJSON, err := json.Marshal(stateForJSON)
	if err != nil {
		return fmt.Errorf("%w: encode state: %w", ErrInvalidStore, err)
	}
	ledgerJSON, err := json.Marshal(commit.State.NonceLedger)
	if err != nil {
		return fmt.Errorf("%w: encode nonce ledger: %w", ErrInvalidStore, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_controlplane_commits (cluster_id, epoch, revision, nonce, leader_id, term, digest, version, payload, state_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, key.ClusterID, int64(key.Epoch), int64(key.Revision), key.Nonce, key.LeaderID, int64(commit.State.Term), key.Digest, commit.State.Desired.Version, []byte(commit.State.Desired.Payload), stateJSON); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrCommitConflict
		}
		return fmt.Errorf("%w: append commit: %w", ErrInvalidStore, err)
	}
	if err := upsertStateTx(ctx, tx, commit.State, ledgerJSON); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit append: %w", ErrInvalidStore, err)
	}
	return nil
}

// CheckpointLeadership persists a metadata-only leader/term/epoch transition
// after native-raft has proven that the desired revision and nonce history are
// unchanged. It never writes a new desired-state commit and therefore cannot
// be used to bypass normal proposal sequencing.
func (s *Store) CheckpointLeadership(ctx context.Context, next controlplane.State) error {
	if s == nil || s.db == nil || ctx == nil || !controlplane.ValidIdentity(next.ClusterID) {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin leadership checkpoint: %w", ErrInvalidStore, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, clusterLockKey(next.ClusterID)); err != nil {
		return fmt.Errorf("%w: lock leadership checkpoint: %w", ErrInvalidStore, err)
	}
	current, err := loadStateTx(ctx, tx, next.ClusterID)
	if err != nil {
		return err
	}
	if err := validateLeadershipCheckpointTransition(current, next); err != nil {
		return err
	}
	ledgerJSON, err := json.Marshal(next.NonceLedger)
	if err != nil {
		return fmt.Errorf("%w: encode checkpoint nonce ledger: %w", ErrInvalidStore, err)
	}
	if err := upsertStateTx(ctx, tx, next, ledgerJSON); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit leadership checkpoint: %w", ErrInvalidStore, err)
	}
	return nil
}

func validateLeadershipCheckpointTransition(current, next controlplane.State) error {
	if current.ClusterID == "" || next.ClusterID != current.ClusterID || next.Revision == 0 || next.Revision != current.Revision {
		return ErrCommitConflict
	}
	if next.Desired.Version != current.Desired.Version || next.Desired.Digest != current.Desired.Digest || string(next.Desired.Payload) != string(current.Desired.Payload) || !sameNonceLedger(current.NonceLedger, next.NonceLedger) {
		return ErrCommitConflict
	}
	if !controlplane.ValidIdentity(next.LeaderID) || next.Term == 0 || next.Epoch == 0 || next.WriteFrozen || next.FreezeReason != "" || next.UpdatedAt.IsZero() || next.UpdatedAt.Before(current.UpdatedAt) {
		return ErrCommitConflict
	}
	if next.Epoch < current.Epoch || next.Term < current.Term {
		return ErrStaleCommit
	}
	if next.Epoch == current.Epoch {
		if next.Term != current.Term || next.LeaderID != current.LeaderID {
			return ErrCommitConflict
		}
		return nil
	}
	if next.Term <= current.Term {
		return ErrStaleCommit
	}
	return nil
}

func sameNonceLedger(left, right map[string]controlplane.Revision) bool {
	if len(left) != len(right) {
		return false
	}
	for nonce, revision := range left {
		if right[nonce] != revision {
			return false
		}
	}
	return true
}

func validateTransition(current controlplane.State, commit controlplane.Commit) error {
	next := commit.State
	if next.Term < current.Term || next.Epoch < current.Epoch || next.Revision < current.Revision {
		return ErrStaleCommit
	}
	if current.WriteFrozen {
		return ErrWritesFrozen
	}
	if next.Revision != current.Revision+1 {
		return ErrSequenceGap
	}
	if current.Revision > 0 && next.Epoch == current.Epoch && (next.Term != current.Term || next.LeaderID != current.LeaderID) {
		return ErrCommitConflict
	}
	if current.Revision > 0 && next.Epoch > current.Epoch && next.Term <= current.Term {
		return ErrCommitConflict
	}
	if len(next.NonceLedger) != len(current.NonceLedger)+1 {
		return ErrCommitConflict
	}
	if _, exists := current.NonceLedger[commit.Fence.Nonce]; exists || next.NonceLedger[commit.Fence.Nonce] != next.Revision {
		return ErrCommitConflict
	}
	for nonce, revision := range current.NonceLedger {
		if next.NonceLedger[nonce] != revision {
			return ErrCommitConflict
		}
	}
	return nil
}

func loadStateTx(ctx context.Context, tx *sql.Tx, clusterID string) (controlplane.State, error) {
	var leader, version, digest, reason string
	var term, epoch, revision int64
	var payload, ledger []byte
	var frozen bool
	var updated time.Time
	err := tx.QueryRowContext(ctx, `SELECT leader_id, term, epoch, revision, desired_version, desired_digest, desired_payload, write_frozen, freeze_reason, updated_at, nonce_ledger FROM cheesewaf_controlplane_state WHERE cluster_id = $1 FOR UPDATE`, clusterID).Scan(&leader, &term, &epoch, &revision, &version, &digest, &payload, &frozen, &reason, &updated, &ledger)
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.State{}, ErrStateNotFound
	}
	if err != nil {
		return controlplane.State{}, fmt.Errorf("%w: lock state: %w", ErrInvalidStore, err)
	}
	return decodeState(clusterID, leader, term, epoch, revision, version, digest, payload, frozen, reason, updated, ledger)
}

func upsertStateTx(ctx context.Context, tx *sql.Tx, state controlplane.State, ledger []byte) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO cheesewaf_controlplane_state (cluster_id, leader_id, term, epoch, revision, desired_version, desired_digest, desired_payload, write_frozen, freeze_reason, updated_at, nonce_ledger) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (cluster_id) DO UPDATE SET leader_id=EXCLUDED.leader_id, term=EXCLUDED.term, epoch=EXCLUDED.epoch, revision=EXCLUDED.revision, desired_version=EXCLUDED.desired_version, desired_digest=EXCLUDED.desired_digest, desired_payload=EXCLUDED.desired_payload, write_frozen=EXCLUDED.write_frozen, freeze_reason=EXCLUDED.freeze_reason, updated_at=EXCLUDED.updated_at, nonce_ledger=EXCLUDED.nonce_ledger`, state.ClusterID, state.LeaderID, int64(state.Term), int64(state.Epoch), int64(state.Revision), state.Desired.Version, state.Desired.Digest, []byte(state.Desired.Payload), state.WriteFrozen, state.FreezeReason, state.UpdatedAt, ledger)
	if err != nil {
		return fmt.Errorf("%w: update state: %w", ErrInvalidStore, err)
	}
	return nil
}

func decodeState(clusterID, leader string, term, epoch, revision int64, version, digest string, payload []byte, frozen bool, reason string, updated time.Time, ledger []byte) (controlplane.State, error) {
	if term < 0 || epoch < 0 || revision < 0 {
		return controlplane.State{}, fmt.Errorf("%w: invalid integer state", ErrInvalidStore)
	}
	if !controlplane.ValidIdentity(clusterID) || (leader != "" && !controlplane.ValidIdentity(leader)) {
		return controlplane.State{}, fmt.Errorf("%w: identity state is invalid", ErrInvalidStore)
	}
	if leader == "" && (term != 0 || epoch != 0 || !frozen) {
		return controlplane.State{}, fmt.Errorf("%w: leader-less state must be frozen and have zero term/epoch", ErrInvalidStore)
	}
	if leader != "" && (term == 0 || epoch == 0) {
		return controlplane.State{}, fmt.Errorf("%w: leader state requires non-zero term/epoch", ErrInvalidStore)
	}
	state := controlplane.State{ClusterID: clusterID, LeaderID: leader, Term: uint64(term), Epoch: controlplane.Epoch(epoch), Revision: controlplane.Revision(revision), Desired: controlplane.DesiredState{Version: version, Digest: digest, Payload: append([]byte(nil), payload...)}, WriteFrozen: frozen, FreezeReason: reason, UpdatedAt: updated}
	if revision > 0 && (!controlplane.ValidIdentity(version) || len(payload) == 0 || !json.Valid(payload) || len(digest) != 64 || digest != strings.ToLower(digest) || digest != controlplane.Digest(payload) || len(ledger) == 0 || updated.IsZero()) {
		return controlplane.State{}, fmt.Errorf("%w: committed state integrity check failed", ErrInvalidStore)
	}
	if len(ledger) > 0 {
		if err := json.Unmarshal(ledger, &state.NonceLedger); err != nil {
			return controlplane.State{}, fmt.Errorf("%w: decode nonce ledger: %w", ErrInvalidStore, err)
		}
		if err := validateNonceLedger(state.NonceLedger, state.Revision); err != nil {
			return controlplane.State{}, err
		}
	}
	return state, nil
}

func validateNonceLedger(ledger map[string]controlplane.Revision, revision controlplane.Revision) error {
	if revision == 0 {
		if len(ledger) != 0 {
			return fmt.Errorf("%w: empty state cannot contain nonce ledger", ErrInvalidStore)
		}
		return nil
	}
	if revision == ^controlplane.Revision(0) {
		return fmt.Errorf("%w: nonce ledger revision overflow", ErrInvalidStore)
	}
	if len(ledger) == 0 || uint64(len(ledger)) != uint64(revision) {
		return fmt.Errorf("%w: committed state nonce ledger is empty", ErrInvalidStore)
	}
	seenRevisions := make(map[controlplane.Revision]struct{}, len(ledger))
	for nonce, entryRevision := range ledger {
		if !controlplane.ValidIdentity(nonce) || entryRevision == 0 || entryRevision > revision {
			return fmt.Errorf("%w: invalid nonce ledger entry", ErrInvalidStore)
		}
		if _, duplicate := seenRevisions[entryRevision]; duplicate {
			return fmt.Errorf("%w: nonce ledger has duplicate revision", ErrInvalidStore)
		}
		seenRevisions[entryRevision] = struct{}{}
	}
	for expected := controlplane.Revision(1); expected <= revision; expected++ {
		if _, ok := seenRevisions[expected]; !ok {
			return fmt.Errorf("%w: nonce ledger is missing a revision", ErrInvalidStore)
		}
	}
	return nil
}

func clusterLockKey(clusterID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(clusterID))
	return int64(h.Sum64())
}

func validateCommitFields(commit controlplane.Commit) error {
	if uint64(commit.State.Term) > math.MaxInt64 || uint64(commit.State.Epoch) > math.MaxInt64 || uint64(commit.State.Revision) > math.MaxInt64 || uint64(commit.Fence.Epoch) > math.MaxInt64 || uint64(commit.Fence.Revision) > math.MaxInt64 {
		return fmt.Errorf("%w: commit integer exceeds PostgreSQL BIGINT", ErrInvalidStore)
	}
	if !controlplane.ValidIdentity(commit.Fence.ClusterID) || !controlplane.ValidIdentity(commit.Fence.LeaderID) || !controlplane.ValidIdentity(commit.Fence.Nonce) || !controlplane.ValidIdentity(commit.State.ClusterID) || !controlplane.ValidIdentity(commit.State.LeaderID) || !controlplane.ValidIdentity(commit.State.Desired.Version) || commit.Fence.Revision == 0 || commit.Fence.Epoch == 0 || commit.State.Term == 0 || commit.State.ClusterID != commit.Fence.ClusterID || commit.State.LeaderID != commit.Fence.LeaderID || commit.State.Epoch != commit.Fence.Epoch || commit.State.Revision != commit.Fence.Revision || commit.State.WriteFrozen || commit.State.UpdatedAt.IsZero() || len(commit.State.Desired.Payload) == 0 || !json.Valid(commit.State.Desired.Payload) || commit.State.Desired.Digest != controlplane.Digest(commit.State.Desired.Payload) || commit.Fence.Digest != commit.State.Desired.Digest || commit.State.NonceLedger[commit.Fence.Nonce] != commit.Fence.Revision {
		return fmt.Errorf("%w: commit fields are inconsistent", ErrInvalidStore)
	}
	if err := validateNonceLedger(commit.State.NonceLedger, commit.State.Revision); err != nil {
		return err
	}
	return nil
}

func sameState(a, b controlplane.State) bool {
	if a.ClusterID != b.ClusterID || a.LeaderID != b.LeaderID || a.Term != b.Term || a.Epoch != b.Epoch || a.Revision != b.Revision || a.Desired.Version != b.Desired.Version || a.Desired.Digest != b.Desired.Digest || !bytesEqual(a.Desired.Payload, b.Desired.Payload) || a.WriteFrozen != b.WriteFrozen || a.FreezeReason != b.FreezeReason || !a.UpdatedAt.Equal(b.UpdatedAt) || len(a.NonceLedger) != len(b.NonceLedger) {
		return false
	}
	for nonce, revision := range a.NonceLedger {
		if b.NonceLedger[nonce] != revision {
			return false
		}
	}
	return true
}
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
