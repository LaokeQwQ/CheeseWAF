package intelstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

// PostgresStore is the PostgreSQL implementation of Store. It accepts an
// existing *sql.DB so callers keep the management-plane pool. The intel tables
// are created by the management schema migration.
type PostgresStore struct {
	db *sql.DB
}

var _ Store = (*PostgresStore)(nil)

// NewPostgres wraps an existing PostgreSQL handle. The caller owns the handle
// and is responsible for running migrations before the first write.
func NewPostgres(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: postgres handle is required", ErrInvalid)
	}
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) UpsertSource(ctx context.Context, source intel.Source) error {
	normalized, err := normalizeSource(source)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO intel_sources (id, type, url, trust, enabled, etag, last_modified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
ON CONFLICT (id) DO UPDATE SET
	type = EXCLUDED.type,
	url = EXCLUDED.url,
	trust = EXCLUDED.trust,
	enabled = EXCLUDED.enabled,
	etag = EXCLUDED.etag,
	last_modified = EXCLUDED.last_modified,
	updated_at = EXCLUDED.updated_at`,
		normalized.ID, normalized.Type, normalized.URL, string(normalized.Trust), normalized.Enabled,
		normalized.ETag, normalized.LastModified, now,
	)
	if err != nil {
		return fmt.Errorf("intelstore: upsert source: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListSources(ctx context.Context) ([]intel.Source, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sourceColumns+` FROM intel_sources ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("intelstore: list sources: %w", err)
	}
	defer rows.Close()
	sources := make([]intel.Source, 0, 8)
	for rows.Next() {
		source, err := scanSource(rows)
		if err != nil {
			return nil, fmt.Errorf("intelstore: scan source: %w", err)
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelstore: list sources: %w", err)
	}
	return sources, nil
}

func (s *PostgresStore) GetSource(ctx context.Context, id string) (intel.Source, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return intel.Source{}, fmt.Errorf("%w: source id must match %s", ErrInvalid, safeIDPattern)
	}
	source, err := scanSource(s.db.QueryRowContext(ctx, `SELECT `+sourceColumns+` FROM intel_sources WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Source{}, ErrNotFound
	}
	if err != nil {
		return intel.Source{}, fmt.Errorf("intelstore: get source: %w", err)
	}
	return source, nil
}

func (s *PostgresStore) InsertItem(ctx context.Context, item intel.Item) (intel.Item, bool, error) {
	normalized, err := normalizeItem(item)
	if err != nil {
		return intel.Item{}, false, err
	}
	external, err := encodeStringList(normalized.ExternalIDs, "external ids")
	if err != nil {
		return intel.Item{}, false, err
	}
	products, err := encodeStringList(normalized.Products, "products")
	if err != nil {
		return intel.Item{}, false, err
	}
	versions, err := encodeStringList(normalized.AffectedVersions, "affected versions")
	if err != nil {
		return intel.Item{}, false, err
	}
	references, err := encodeStringList(normalized.References, "references")
	if err != nil {
		return intel.Item{}, false, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO intel_items (id, source_id, external_ids, title, content_hash, published_at, products, affected_versions, attack_vector, exploit_status, references_json, raw_excerpt, created_at)
VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7::jsonb, $8::jsonb, $9, $10, $11::jsonb, $12, $13)
ON CONFLICT (source_id, content_hash) DO NOTHING`,
		normalized.ID, normalized.SourceID, external, normalized.Title, normalized.ContentHash,
		normalized.PublishedAt.UTC(), products, versions, normalized.AttackVector,
		normalized.ExploitStatus, references, normalized.RawExcerpt, time.Now().UTC(),
	)
	if err != nil {
		return intel.Item{}, false, fmt.Errorf("intelstore: insert item: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return intel.Item{}, false, fmt.Errorf("intelstore: insert item: %w", err)
	}
	if affected > 0 {
		return normalized, true, nil
	}
	existing, err := s.itemByContentHash(ctx, normalized.SourceID, normalized.ContentHash)
	if err != nil {
		return intel.Item{}, false, err
	}
	return existing, false, nil
}

func (s *PostgresStore) itemByContentHash(ctx context.Context, sourceID, contentHash string) (intel.Item, error) {
	item, err := scanItem(s.db.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM intel_items WHERE source_id = $1 AND content_hash = $2`,
		sourceID, contentHash))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Item{}, ErrNotFound
	}
	if err != nil {
		return intel.Item{}, fmt.Errorf("intelstore: get item by content hash: %w", err)
	}
	return item, nil
}

func (s *PostgresStore) ListItems(ctx context.Context, filter ItemFilter) ([]intel.Item, error) {
	if err := validateStateFilter(filter.State); err != nil {
		return nil, err
	}
	state := string(filter.State)
	rows, err := s.db.QueryContext(ctx, `
SELECT `+itemColumns+`
FROM intel_items
WHERE ($1 = '' OR EXISTS (SELECT 1 FROM rule_candidates c WHERE c.item_id = intel_items.id AND c.state = $1))
ORDER BY published_at DESC, id ASC
LIMIT $2`, state, clampLimit(filter.Limit))
	if err != nil {
		return nil, fmt.Errorf("intelstore: list items: %w", err)
	}
	defer rows.Close()
	items := make([]intel.Item, 0, 16)
	for rows.Next() {
		item, err := scanItem(rows)
		if err != nil {
			return nil, fmt.Errorf("intelstore: scan item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelstore: list items: %w", err)
	}
	return items, nil
}

func (s *PostgresStore) GetItem(ctx context.Context, id string) (intel.Item, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return intel.Item{}, fmt.Errorf("%w: item id must match %s", ErrInvalid, safeIDPattern)
	}
	item, err := scanItem(s.db.QueryRowContext(ctx, `SELECT `+itemColumns+` FROM intel_items WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Item{}, ErrNotFound
	}
	if err != nil {
		return intel.Item{}, fmt.Errorf("intelstore: get item: %w", err)
	}
	return item, nil
}

func (s *PostgresStore) InsertCandidate(ctx context.Context, candidate intel.Candidate) (intel.Candidate, bool, error) {
	normalized, err := normalizeCandidate(candidate)
	if err != nil {
		return intel.Candidate{}, false, err
	}
	provenance, err := encodeProvenance(normalized.Provenance)
	if err != nil {
		return intel.Candidate{}, false, err
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO rule_candidates (id, item_id, site_id, rule_json, action, state, confidence, provenance_json, expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8::jsonb, $9, $10, $11)
ON CONFLICT (id) DO NOTHING`,
		normalized.ID, normalized.ItemID, normalized.SiteID, normalized.RuleJSON, normalized.Action,
		string(normalized.State), normalized.Confidence, provenance,
		normalized.CreatedAt.Add(normalized.TTL), normalized.CreatedAt, now,
	)
	if err != nil {
		return intel.Candidate{}, false, fmt.Errorf("intelstore: insert candidate: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return intel.Candidate{}, false, fmt.Errorf("intelstore: insert candidate: %w", err)
	}
	if affected > 0 {
		return normalized, true, nil
	}
	existing, err := s.GetCandidate(ctx, normalized.ID)
	if err != nil {
		return intel.Candidate{}, false, err
	}
	return existing, false, nil
}

func (s *PostgresStore) ListCandidates(ctx context.Context, filter CandidateFilter) ([]intel.Candidate, error) {
	if err := validateStateFilter(filter.State); err != nil {
		return nil, err
	}
	siteID := strings.TrimSpace(filter.SiteID)
	if siteID != "" && !safeIDPattern.MatchString(siteID) {
		return nil, fmt.Errorf("%w: site id must match %s", ErrInvalid, safeIDPattern)
	}
	state := string(filter.State)
	rows, err := s.db.QueryContext(ctx, `
SELECT `+candidateColumns+`
FROM rule_candidates
WHERE ($1 = '' OR site_id = $1) AND ($2 = '' OR state = $2)
ORDER BY created_at DESC, id ASC
LIMIT $3`, siteID, state, clampLimit(filter.Limit))
	if err != nil {
		return nil, fmt.Errorf("intelstore: list candidates: %w", err)
	}
	defer rows.Close()
	candidates := make([]intel.Candidate, 0, 16)
	for rows.Next() {
		candidate, err := scanCandidate(rows)
		if err != nil {
			return nil, fmt.Errorf("intelstore: scan candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelstore: list candidates: %w", err)
	}
	return candidates, nil
}

func (s *PostgresStore) GetCandidate(ctx context.Context, id string) (intel.Candidate, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return intel.Candidate{}, fmt.Errorf("%w: candidate id must match %s", ErrInvalid, safeIDPattern)
	}
	candidate, err := scanCandidate(s.db.QueryRowContext(ctx, `SELECT `+candidateColumns+` FROM rule_candidates WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Candidate{}, ErrNotFound
	}
	if err != nil {
		return intel.Candidate{}, fmt.Errorf("intelstore: get candidate: %w", err)
	}
	return candidate, nil
}

func (s *PostgresStore) UpdateCandidate(ctx context.Context, id string, update CandidateUpdate) (intel.Candidate, error) {
	candidate, err := s.GetCandidate(ctx, id)
	if err != nil {
		return intel.Candidate{}, err
	}
	if update.State != nil {
		candidate.State = intel.CandidateState(strings.ToLower(strings.TrimSpace(string(*update.State))))
	}
	if update.Action != nil {
		action := strings.ToLower(strings.TrimSpace(*update.Action))
		rewritten, err := RewriteRuleAction(candidate.RuleJSON, action)
		if err != nil {
			return intel.Candidate{}, err
		}
		candidate.RuleJSON = rewritten
		candidate.Action = action
	}
	if update.ApprovedBy != "" {
		approver, err := normalizeApprover(update.ApprovedBy)
		if err != nil {
			return intel.Candidate{}, err
		}
		candidate.Provenance.Approved = true
		candidate.Provenance.ApprovedBy = approver
	}
	if update.ExpiresAt != nil {
		ttl := update.ExpiresAt.UTC().Sub(candidate.CreatedAt)
		if ttl <= 0 || ttl > intel.MaxCandidateTTL {
			return intel.Candidate{}, fmt.Errorf("%w: candidate expiry is out of range", ErrInvalid)
		}
		candidate.TTL = ttl
	}
	normalized, err := normalizeCandidate(candidate)
	if err != nil {
		return intel.Candidate{}, err
	}
	provenance, err := encodeProvenance(normalized.Provenance)
	if err != nil {
		return intel.Candidate{}, err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE rule_candidates
SET rule_json = $1::jsonb, action = $2, state = $3, confidence = $4, provenance_json = $5::jsonb, expires_at = $6, updated_at = $7
WHERE id = $8`,
		normalized.RuleJSON, normalized.Action, string(normalized.State), normalized.Confidence, provenance,
		normalized.CreatedAt.Add(normalized.TTL), time.Now().UTC(), normalized.ID,
	)
	if err != nil {
		return intel.Candidate{}, fmt.Errorf("intelstore: update candidate: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return intel.Candidate{}, fmt.Errorf("intelstore: update candidate: %w", err)
	}
	if affected == 0 {
		return intel.Candidate{}, ErrNotFound
	}
	return normalized, nil
}

func (s *PostgresStore) UpdateCandidateState(ctx context.Context, id string, state intel.CandidateState, approvedBy string) (intel.Candidate, error) {
	return s.UpdateCandidate(ctx, id, CandidateUpdate{State: &state, ApprovedBy: approvedBy})
}

func (s *PostgresStore) UpdateCandidateAction(ctx context.Context, id string, action, approvedBy string) (intel.Candidate, error) {
	return s.UpdateCandidate(ctx, id, CandidateUpdate{Action: &action, ApprovedBy: approvedBy})
}

func (s *PostgresStore) UpdateCandidateExpiry(ctx context.Context, id string, expiresAt time.Time) (intel.Candidate, error) {
	return s.UpdateCandidate(ctx, id, CandidateUpdate{ExpiresAt: &expiresAt})
}

func (s *PostgresStore) ExpireCandidates(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
UPDATE rule_candidates
SET state = 'expired', updated_at = $1
WHERE state IN ('draft', 'shadow', 'canary', 'active')
  AND expires_at <= $1`, now.UTC())
	if err != nil {
		return 0, fmt.Errorf("intelstore: expire candidates: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("intelstore: expire candidates: %w", err)
	}
	return affected, nil
}

func (s *PostgresStore) InsertImportJob(ctx context.Context, job ImportJob) error {
	normalized, err := normalizeJob(job)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO intel_import_jobs (id, url, content_hash, status, extraction_json, error, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)`,
		normalized.ID, normalized.URL, normalized.ContentHash, normalized.Status, normalized.ExtractionJSON,
		normalized.Error, normalized.CreatedAt, normalized.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("intelstore: insert import job: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateImportJob(ctx context.Context, job ImportJob) error {
	normalized, err := normalizeJob(job)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE intel_import_jobs
SET url = $1, content_hash = $2, status = $3, extraction_json = $4::jsonb, error = $5, updated_at = $6
WHERE id = $7`,
		normalized.URL, normalized.ContentHash, normalized.Status, normalized.ExtractionJSON,
		normalized.Error, normalized.UpdatedAt, normalized.ID,
	)
	if err != nil {
		return fmt.Errorf("intelstore: update import job: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("intelstore: update import job: %w", err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) GetImportJob(ctx context.Context, id string) (ImportJob, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return ImportJob{}, fmt.Errorf("%w: import job id must match %s", ErrInvalid, safeIDPattern)
	}
	job, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM intel_import_jobs WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ImportJob{}, ErrNotFound
	}
	if err != nil {
		return ImportJob{}, fmt.Errorf("intelstore: get import job: %w", err)
	}
	return job, nil
}
