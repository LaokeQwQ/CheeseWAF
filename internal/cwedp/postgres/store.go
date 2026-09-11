// Package postgres provides the durable PostgreSQL ResumeStore adapter for CWEDP.
package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const resumeTable = "cheesewaf_cwedp_resume_state"

var (
	ErrInvalidStore   = errors.New("invalid CWEDP PostgreSQL resume store")
	ErrInvalidState   = errors.New("invalid CWEDP resume state")
	ErrOffsetConflict = cwedp.ErrResumeOffsetConflict
	ErrStateConflict  = cwedp.ErrStateConflict
	ErrTerminalState  = errors.New("CWEDP resume state is terminal")
	ErrJobNotFound    = cwedp.ErrJobNotFound
)

// ResumeStore implements cwedp.ResumeStore without opening any transfer network connection.
type ResumeStore struct{ db *sql.DB }

var _ cwedp.ResumeStore = (*ResumeStore)(nil)

func New(db *sql.DB) (*ResumeStore, error) {
	if db == nil {
		return nil, ErrInvalidStore
	}
	return &ResumeStore{db: db}, nil
}

func Open(ctx context.Context, dsn string) (*ResumeStore, error) {
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

func (s *ResumeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Migrate is transactional and repeatable. Raw transfer bytes are stored only
// in the BYTEA data column; the JSONB column contains the public source list.
func (s *ResumeStore) Migrate(ctx context.Context) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin migration: %w", ErrInvalidStore, err)
	}
	defer func() { _ = tx.Rollback() }()
	statement := `CREATE TABLE IF NOT EXISTS cheesewaf_cwedp_resume_state (
		job_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL, package_id TEXT NOT NULL, version TEXT NOT NULL,
		artifact_size BIGINT NOT NULL CHECK (artifact_size >= 0 AND artifact_size <= 1073741824),
		md5 TEXT NOT NULL CHECK (md5 ~ '^[0-9a-f]{32}$'),
		sha1 TEXT NOT NULL CHECK (sha1 ~ '^[0-9a-f]{40}$'),
		sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
		sources JSONB NOT NULL, signature TEXT NOT NULL DEFAULT '',
		source_kind TEXT NOT NULL, source_id TEXT NOT NULL, source_trust_root TEXT NOT NULL DEFAULT '',
		source_organization TEXT NOT NULL DEFAULT '', source_certificate_fingerprint TEXT NOT NULL DEFAULT '',
		max_chunk BIGINT NOT NULL CHECK (max_chunk > 0 AND max_chunk <= 8388608),
		quarantined_sources JSONB NOT NULL DEFAULT '[]'::jsonb,
		source_switches INTEGER NOT NULL DEFAULT 0 CHECK (source_switches >= 0 AND source_switches <= 3),
		max_source_switches INTEGER NOT NULL DEFAULT 3 CHECK (max_source_switches > 0 AND max_source_switches <= 3),
		next_offset BIGINT NOT NULL CHECK (next_offset >= 0 AND next_offset <= artifact_size),
		data BYTEA NOT NULL, complete BOOLEAN NOT NULL, failed BOOLEAN NOT NULL,
		failure TEXT NOT NULL DEFAULT '', updated_at TIMESTAMPTZ NOT NULL,
		CHECK (octet_length(data) = next_offset),
		CHECK (NOT (complete AND failed)),
		CHECK (NOT complete OR next_offset = artifact_size),
		CHECK ((failed AND failure <> '') OR (NOT failed AND failure = ''))
	)`
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("%w: migration statement: %w", ErrInvalidStore, err)
	}
	for _, alter := range []string{
		`ALTER TABLE cheesewaf_cwedp_resume_state ADD COLUMN IF NOT EXISTS quarantined_sources JSONB NOT NULL DEFAULT '[]'::jsonb`,
		`ALTER TABLE cheesewaf_cwedp_resume_state ADD COLUMN IF NOT EXISTS source_switches INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE cheesewaf_cwedp_resume_state ADD COLUMN IF NOT EXISTS max_source_switches INTEGER NOT NULL DEFAULT 3`,
	} {
		if _, err := tx.ExecContext(ctx, alter); err != nil {
			return fmt.Errorf("%w: migration alter: %w", ErrInvalidStore, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit migration: %w", ErrInvalidStore, err)
	}
	return nil
}

// Save satisfies cwedp.ResumeStore. It serializes a job and permits only an
// idempotent replay, a validated append, or a transition to a terminal state.
func (s *ResumeStore) Save(ctx context.Context, state cwedp.ResumeState) error {
	return s.save(ctx, nil, state)
}

// SaveExpected applies state only if the persisted next offset equals
// expectedOffset. Callers that perform a load/modify/save cycle should use this
// method to reject stale writers explicitly.
func (s *ResumeStore) SaveExpected(ctx context.Context, expectedOffset int64, state cwedp.ResumeState) error {
	return s.save(ctx, &expectedOffset, state)
}

func (s *ResumeStore) save(ctx context.Context, expectedOffset *int64, state cwedp.ResumeState) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if err := validateState(state); err != nil {
		return err
	}
	if expectedOffset != nil && (*expectedOffset < 0 || *expectedOffset > state.Intent.Size) {
		return ErrOffsetConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin save: %w", ErrInvalidStore, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey(state.JobID)); err != nil {
		return fmt.Errorf("%w: lock job: %w", ErrInvalidStore, err)
	}
	current, err := loadTx(ctx, tx, state.JobID, true)
	if errors.Is(err, ErrJobNotFound) {
		if expectedOffset != nil && *expectedOffset != 0 {
			return ErrOffsetConflict
		}
		if state.NextOffset != 0 {
			return ErrOffsetConflict
		}
		if err := insertTx(ctx, tx, state); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if !sameImmutableState(current, state) {
			return ErrStateConflict
		}
		if sameState(current, state) {
			return commitTx(tx, "idempotent save")
		}
		if current.Complete || (current.Failed && current.Source == state.Source) {
			return ErrTerminalState
		}
		if expectedOffset != nil && current.NextOffset != *expectedOffset {
			return ErrOffsetConflict
		}
		if err := validateTransition(current, state); err != nil {
			return err
		}
		result, err := updateTx(ctx, tx, current.NextOffset, state)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("%w: update result: %w", ErrInvalidStore, err)
		} else if affected != 1 {
			return ErrOffsetConflict
		}
	}
	return commitTx(tx, "save")
}

func (s *ResumeStore) Load(ctx context.Context, jobID string) (cwedp.ResumeState, error) {
	if s == nil || s.db == nil || ctx == nil || strings.TrimSpace(jobID) == "" {
		return cwedp.ResumeState{}, ErrInvalidStore
	}
	return loadRow(s.db.QueryRowContext(ctx, selectState+` WHERE job_id=$1`, strings.TrimSpace(jobID)))
}

const selectState = `SELECT job_id,intent_id,package_id,version,artifact_size,md5,sha1,sha256,sources,signature,source_kind,source_id,source_trust_root,source_organization,source_certificate_fingerprint,max_chunk,quarantined_sources,source_switches,max_source_switches,next_offset,data,complete,failed,failure,updated_at FROM cheesewaf_cwedp_resume_state`

func loadTx(ctx context.Context, tx *sql.Tx, jobID string, forUpdate bool) (cwedp.ResumeState, error) {
	query := selectState + ` WHERE job_id=$1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	return loadRow(tx.QueryRowContext(ctx, query, jobID))
}

type rowScanner interface{ Scan(...any) error }

func loadRow(row rowScanner) (cwedp.ResumeState, error) {
	var state cwedp.ResumeState
	var sourcesJSON []byte
	var size, maxChunk, offset int64
	var sourceSwitches, maxSourceSwitches int
	var md5Digest, sha1Digest, sha256Digest, sourceKind string
	var quarantinesJSON []byte
	err := row.Scan(&state.JobID, &state.Intent.ID, &state.Intent.PackageID, &state.Intent.Version, &size, &md5Digest, &sha1Digest, &sha256Digest, &sourcesJSON, &state.Intent.Signature, &sourceKind, &state.Source.ID, &state.Source.TrustRoot, &state.Source.Organization, &state.Source.CertificateFingerprint, &maxChunk, &quarantinesJSON, &sourceSwitches, &maxSourceSwitches, &offset, &state.Data, &state.Complete, &state.Failed, &state.Failure, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return cwedp.ResumeState{}, ErrJobNotFound
	}
	if err != nil {
		return cwedp.ResumeState{}, fmt.Errorf("%w: load: %w", ErrInvalidStore, err)
	}
	state.Intent.Size = size
	state.Intent.Digests = cwedp.Digests{MD5: md5Digest, SHA1: sha1Digest, SHA256: sha256Digest}
	state.Source.Kind = cwedp.SourceKind(sourceKind)
	state.MaxChunk, state.NextOffset = maxChunk, offset
	state.SourceSwitches, state.MaxSourceSwitches = sourceSwitches, maxSourceSwitches
	if state.MaxSourceSwitches == 0 {
		// Rows written before quarantine support inherit the platform default.
		state.MaxSourceSwitches = cwedp.DefaultMaxSourceSwitches
	}
	if err := json.Unmarshal(sourcesJSON, &state.Intent.Sources); err != nil {
		return cwedp.ResumeState{}, fmt.Errorf("%w: decode sources: %w", ErrInvalidState, err)
	}
	if len(quarantinesJSON) == 0 {
		quarantinesJSON = []byte(`[]`)
	}
	if err := json.Unmarshal(quarantinesJSON, &state.QuarantinedSources); err != nil {
		return cwedp.ResumeState{}, fmt.Errorf("%w: decode quarantines: %w", ErrInvalidState, err)
	}
	state.Data = append([]byte(nil), state.Data...)
	if err := validateState(state); err != nil {
		return cwedp.ResumeState{}, err
	}
	return state, nil
}

func insertTx(ctx context.Context, tx *sql.Tx, state cwedp.ResumeState) error {
	sources, err := json.Marshal(state.Intent.Sources)
	if err != nil {
		return fmt.Errorf("%w: encode sources: %w", ErrInvalidState, err)
	}
	quarantines, err := json.Marshal(state.QuarantinedSources)
	if err != nil {
		return fmt.Errorf("%w: encode quarantines: %w", ErrInvalidState, err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO cheesewaf_cwedp_resume_state (job_id,intent_id,package_id,version,artifact_size,md5,sha1,sha256,sources,signature,source_kind,source_id,source_trust_root,source_organization,source_certificate_fingerprint,max_chunk,next_offset,data,complete,failed,failure,updated_at,quarantined_sources,source_switches,max_source_switches) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`, stateArgs(state, sources, quarantines)...)
	if err != nil {
		return fmt.Errorf("%w: insert state: %w", ErrInvalidStore, err)
	}
	return nil
}

func updateTx(ctx context.Context, tx *sql.Tx, expectedOffset int64, state cwedp.ResumeState) (sql.Result, error) {
	sources, err := json.Marshal(state.Intent.Sources)
	if err != nil {
		return nil, fmt.Errorf("%w: encode sources: %w", ErrInvalidState, err)
	}
	quarantines, err := json.Marshal(state.QuarantinedSources)
	if err != nil {
		return nil, fmt.Errorf("%w: encode quarantines: %w", ErrInvalidState, err)
	}
	args := stateArgs(state, sources, quarantines)
	args = append(args, expectedOffset)
	result, err := tx.ExecContext(ctx, `UPDATE cheesewaf_cwedp_resume_state SET intent_id=$2,package_id=$3,version=$4,artifact_size=$5,md5=$6,sha1=$7,sha256=$8,sources=$9,signature=$10,source_kind=$11,source_id=$12,source_trust_root=$13,source_organization=$14,source_certificate_fingerprint=$15,max_chunk=$16,next_offset=$17,data=$18,complete=$19,failed=$20,failure=$21,updated_at=$22,quarantined_sources=$23,source_switches=$24,max_source_switches=$25 WHERE job_id=$1 AND next_offset=$26 AND NOT complete`, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: update state: %w", ErrInvalidStore, err)
	}
	return result, nil
}

func stateArgs(state cwedp.ResumeState, sources, quarantines []byte) []any {
	data := []byte(state.Data)
	if data == nil {
		data = []byte{}
	}
	if quarantines == nil {
		quarantines = []byte(`[]`)
	}
	return []any{state.JobID, state.Intent.ID, state.Intent.PackageID, state.Intent.Version, state.Intent.Size, state.Intent.Digests.MD5, state.Intent.Digests.SHA1, state.Intent.Digests.SHA256, sources, state.Intent.Signature, string(state.Source.Kind), state.Source.ID, state.Source.TrustRoot, state.Source.Organization, state.Source.CertificateFingerprint, state.MaxChunk, state.NextOffset, data, state.Complete, state.Failed, state.Failure, state.UpdatedAt, quarantines, state.SourceSwitches, state.MaxSourceSwitches}
}

func validateState(state cwedp.ResumeState) error {
	if strings.TrimSpace(state.JobID) == "" || state.JobID != state.Intent.ID || state.MaxChunk <= 0 || state.MaxChunk > cwedp.DefaultMaxChunkBytes || state.MaxSourceSwitches <= 0 || state.MaxSourceSwitches > cwedp.DefaultMaxSourceSwitches || state.SourceSwitches < 0 || state.SourceSwitches > state.MaxSourceSwitches || state.SourceSwitches != len(state.QuarantinedSources) || state.NextOffset < 0 || state.NextOffset > state.Intent.Size || int64(len(state.Data)) != state.NextOffset || state.UpdatedAt.IsZero() || state.Complete && state.Failed || state.Complete && state.NextOffset != state.Intent.Size || state.Failed != (state.Failure != "") {
		return ErrInvalidState
	}
	if err := state.Intent.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	if err := cwedp.ValidateSourceQuarantines(state.Intent, state.QuarantinedSources); err != nil {
		return fmt.Errorf("%w: quarantines: %v", ErrInvalidState, err)
	}
	sourceFound := false
	for _, source := range state.Intent.Sources {
		if source == state.Source {
			sourceFound = true
			break
		}
	}
	if !sourceFound {
		return ErrInvalidState
	}
	if state.Complete {
		if err := cwedp.VerifyDigests(state.Data, state.Intent.Digests); err != nil {
			return fmt.Errorf("%w: complete digest verification: %v", ErrInvalidState, err)
		}
	}
	return nil
}

func validateTransition(current, next cwedp.ResumeState) error {
	if err := cwedp.ValidateResumeTransition(current, next); err != nil {
		if errors.Is(err, cwedp.ErrStateConflict) {
			return ErrStateConflict
		}
		if errors.Is(err, cwedp.ErrSourceSwitchLimit) {
			return ErrOffsetConflict
		}
		return ErrOffsetConflict
	}
	return nil
}

func sameImmutableState(a, b cwedp.ResumeState) bool {
	return a.JobID == b.JobID && reflect.DeepEqual(a.Intent, b.Intent) && a.MaxChunk == b.MaxChunk && (a.MaxSourceSwitches == b.MaxSourceSwitches || a.MaxSourceSwitches == 0 || b.MaxSourceSwitches == 0)
}

func sameState(a, b cwedp.ResumeState) bool {
	return sameImmutableState(a, b) && a.Source == b.Source && sameQuarantines(a.QuarantinedSources, b.QuarantinedSources) && a.SourceSwitches == b.SourceSwitches && a.NextOffset == b.NextOffset && bytes.Equal(a.Data, b.Data) && a.Complete == b.Complete && a.Failed == b.Failed && a.Failure == b.Failure && a.UpdatedAt.Equal(b.UpdatedAt)
}

func sameQuarantines(a, b []cwedp.SourceQuarantine) bool {
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

func lockKey(jobID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(jobID))
	return int64(h.Sum64())
}

func commitTx(tx *sql.Tx, operation string) error {
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: %s commit: %w", ErrInvalidStore, operation, err)
	}
	return nil
}
