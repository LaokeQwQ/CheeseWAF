package intelstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

// SQLiteStore is the SQLite implementation of Store. It accepts an existing
// *sql.DB so callers keep a single connection pool for the whole process. The
// intel tables are created by the management schema migration.
type SQLiteStore struct {
	db *sql.DB
}

var _ Store = (*SQLiteStore)(nil)

// NewSQLite wraps an existing SQLite handle. The caller owns the handle and is
// responsible for running migrations before the first write.
func NewSQLite(db *sql.DB) (*SQLiteStore, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: sqlite handle is required", ErrInvalid)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) UpsertSource(ctx context.Context, source intel.Source) error {
	normalized, err := normalizeSource(source)
	if err != nil {
		return err
	}
	now := formatSQLiteTime(time.Now().UTC())
	_, err = s.db.ExecContext(ctx, `
INSERT INTO intel_sources (id, type, url, trust, enabled, etag, last_modified, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	type = excluded.type,
	url = excluded.url,
	trust = excluded.trust,
	enabled = excluded.enabled,
	etag = excluded.etag,
	last_modified = excluded.last_modified,
	updated_at = excluded.updated_at`,
		normalized.ID, normalized.Type, normalized.URL, string(normalized.Trust), boolToInt(normalized.Enabled),
		normalized.ETag, normalized.LastModified, now, now,
	)
	if err != nil {
		return fmt.Errorf("intelstore: upsert source: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListSources(ctx context.Context) ([]intel.Source, error) {
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

func (s *SQLiteStore) GetSource(ctx context.Context, id string) (intel.Source, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return intel.Source{}, fmt.Errorf("%w: source id must match %s", ErrInvalid, safeIDPattern)
	}
	source, err := scanSource(s.db.QueryRowContext(ctx, `SELECT `+sourceColumns+` FROM intel_sources WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Source{}, ErrNotFound
	}
	if err != nil {
		return intel.Source{}, fmt.Errorf("intelstore: get source: %w", err)
	}
	return source, nil
}

func (s *SQLiteStore) InsertItem(ctx context.Context, item intel.Item) (intel.Item, bool, error) {
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
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source_id, content_hash) DO NOTHING`,
		normalized.ID, normalized.SourceID, external, normalized.Title, normalized.ContentHash,
		formatSQLiteTime(normalized.PublishedAt), products, versions, normalized.AttackVector,
		normalized.ExploitStatus, references, normalized.RawExcerpt, formatSQLiteTime(time.Now().UTC()),
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

func (s *SQLiteStore) itemByContentHash(ctx context.Context, sourceID, contentHash string) (intel.Item, error) {
	item, err := scanItem(s.db.QueryRowContext(ctx,
		`SELECT `+itemColumns+` FROM intel_items WHERE source_id = ? AND content_hash = ?`,
		sourceID, contentHash))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Item{}, ErrNotFound
	}
	if err != nil {
		return intel.Item{}, fmt.Errorf("intelstore: get item by content hash: %w", err)
	}
	return item, nil
}

func (s *SQLiteStore) ListItems(ctx context.Context, filter ItemFilter) ([]intel.Item, error) {
	if err := validateStateFilter(filter.State); err != nil {
		return nil, err
	}
	state := string(filter.State)
	rows, err := s.db.QueryContext(ctx, `
SELECT `+itemColumns+`
FROM intel_items
WHERE (? = '' OR EXISTS (SELECT 1 FROM rule_candidates c WHERE c.item_id = intel_items.id AND c.state = ?))
ORDER BY published_at DESC, id ASC
LIMIT ?`, state, state, clampLimit(filter.Limit))
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

func (s *SQLiteStore) GetItem(ctx context.Context, id string) (intel.Item, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return intel.Item{}, fmt.Errorf("%w: item id must match %s", ErrInvalid, safeIDPattern)
	}
	item, err := scanItem(s.db.QueryRowContext(ctx, `SELECT `+itemColumns+` FROM intel_items WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Item{}, ErrNotFound
	}
	if err != nil {
		return intel.Item{}, fmt.Errorf("intelstore: get item: %w", err)
	}
	return item, nil
}

func (s *SQLiteStore) InsertCandidate(ctx context.Context, candidate intel.Candidate) (intel.Candidate, bool, error) {
	normalized, err := normalizeCandidate(candidate)
	if err != nil {
		return intel.Candidate{}, false, err
	}
	provenance, err := encodeProvenance(normalized.Provenance)
	if err != nil {
		return intel.Candidate{}, false, err
	}
	now := formatSQLiteTime(time.Now().UTC())
	result, err := s.db.ExecContext(ctx, `
INSERT INTO rule_candidates (id, item_id, site_id, rule_json, action, state, confidence, provenance_json, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO NOTHING`,
		normalized.ID, normalized.ItemID, normalized.SiteID, normalized.RuleJSON, normalized.Action,
		string(normalized.State), normalized.Confidence, provenance,
		formatSQLiteTime(normalized.CreatedAt.Add(normalized.TTL)), formatSQLiteTime(normalized.CreatedAt), now,
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

func (s *SQLiteStore) ListCandidates(ctx context.Context, filter CandidateFilter) ([]intel.Candidate, error) {
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
WHERE (? = '' OR site_id = ?) AND (? = '' OR state = ?)
ORDER BY created_at DESC, id ASC
LIMIT ?`, siteID, siteID, state, state, clampLimit(filter.Limit))
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

func (s *SQLiteStore) GetCandidate(ctx context.Context, id string) (intel.Candidate, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return intel.Candidate{}, fmt.Errorf("%w: candidate id must match %s", ErrInvalid, safeIDPattern)
	}
	candidate, err := scanCandidate(s.db.QueryRowContext(ctx, `SELECT `+candidateColumns+` FROM rule_candidates WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return intel.Candidate{}, ErrNotFound
	}
	if err != nil {
		return intel.Candidate{}, fmt.Errorf("intelstore: get candidate: %w", err)
	}
	return candidate, nil
}

func (s *SQLiteStore) UpdateCandidate(ctx context.Context, id string, update CandidateUpdate) (intel.Candidate, error) {
	candidate, err := s.GetCandidate(ctx, id)
	if err != nil {
		return intel.Candidate{}, err
	}
	previousState := candidate.State
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
	updatedAt := time.Now().UTC()
	if !update.Now.IsZero() {
		updatedAt = update.Now.UTC()
	}
	// Re-approving a candidate that is already in shadow must not restart the
	// observation window; only a real state transition gets a new timestamp.
	// Compare against the state before the update: candidate.State already
	// holds the target state, so using it would preserve the timestamp even
	// when this call is what opened the window.
	if previousState == intel.CandidateShadow && !candidate.UpdatedAt.IsZero() &&
		(update.State == nil || *update.State == previousState) {
		updatedAt = candidate.UpdatedAt
	}
	query := `
UPDATE rule_candidates
SET rule_json = ?, action = ?, state = ?, confidence = ?, provenance_json = ?, expires_at = ?, updated_at = ?
WHERE id = ?`
	args := []any{
		normalized.RuleJSON, normalized.Action, string(normalized.State), normalized.Confidence, provenance,
		formatSQLiteTime(normalized.CreatedAt.Add(normalized.TTL)), formatSQLiteTime(updatedAt), normalized.ID,
	}
	if update.ExpectedState != nil {
		query += ` AND state = ?`
		args = append(args, string(*update.ExpectedState))
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return intel.Candidate{}, fmt.Errorf("intelstore: update candidate: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return intel.Candidate{}, fmt.Errorf("intelstore: update candidate: %w", err)
	}
	if affected == 0 {
		if update.ExpectedState != nil {
			return intel.Candidate{}, ErrConflict
		}
		return intel.Candidate{}, ErrNotFound
	}
	normalized.UpdatedAt = updatedAt
	return normalized, nil
}

func (s *SQLiteStore) UpdateCandidateState(ctx context.Context, id string, state intel.CandidateState, approvedBy string) (intel.Candidate, error) {
	return s.UpdateCandidate(ctx, id, CandidateUpdate{State: &state, ApprovedBy: approvedBy})
}

func (s *SQLiteStore) UpdateCandidateAction(ctx context.Context, id string, action, approvedBy string) (intel.Candidate, error) {
	return s.UpdateCandidate(ctx, id, CandidateUpdate{Action: &action, ApprovedBy: approvedBy})
}

func (s *SQLiteStore) UpdateCandidateExpiry(ctx context.Context, id string, expiresAt time.Time) (intel.Candidate, error) {
	return s.UpdateCandidate(ctx, id, CandidateUpdate{ExpiresAt: &expiresAt})
}

func (s *SQLiteStore) ExpireCandidates(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
UPDATE rule_candidates
SET state = 'expired', updated_at = ?
WHERE state IN ('draft', 'shadow', 'canary', 'active')
  AND julianday(expires_at) <= julianday(?)`,
		formatSQLiteTime(now.UTC()), formatSQLiteTime(now.UTC()),
	)
	if err != nil {
		return 0, fmt.Errorf("intelstore: expire candidates: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("intelstore: expire candidates: %w", err)
	}
	return affected, nil
}

func (s *SQLiteStore) InsertImportJob(ctx context.Context, job ImportJob) error {
	normalized, err := normalizeJob(job)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO intel_import_jobs (id, url, content_hash, status, extraction_json, error, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		normalized.ID, normalized.URL, normalized.ContentHash, normalized.Status, normalized.ExtractionJSON,
		normalized.Error, formatSQLiteTime(normalized.CreatedAt), formatSQLiteTime(normalized.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("intelstore: insert import job: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateImportJob(ctx context.Context, job ImportJob) error {
	normalized, err := normalizeJob(job)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE intel_import_jobs
SET url = ?, content_hash = ?, status = ?, extraction_json = ?, error = ?, updated_at = ?
WHERE id = ?`,
		normalized.URL, normalized.ContentHash, normalized.Status, normalized.ExtractionJSON,
		normalized.Error, formatSQLiteTime(normalized.UpdatedAt), normalized.ID,
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

func (s *SQLiteStore) GetImportJob(ctx context.Context, id string) (ImportJob, error) {
	id = strings.TrimSpace(id)
	if !safeIDPattern.MatchString(id) {
		return ImportJob{}, fmt.Errorf("%w: import job id must match %s", ErrInvalid, safeIDPattern)
	}
	job, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM intel_import_jobs WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ImportJob{}, ErrNotFound
	}
	if err != nil {
		return ImportJob{}, fmt.Errorf("intelstore: get import job: %w", err)
	}
	return job, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func encodeProvenance(provenance intel.Provenance) (string, error) {
	encoded, err := json.Marshal(provenance)
	if err != nil {
		return "", fmt.Errorf("%w: encode candidate provenance: %v", ErrInvalid, err)
	}
	if len(encoded) > maxProvenanceBytes {
		return "", fmt.Errorf("%w: candidate provenance exceeds %d bytes", ErrInvalid, maxProvenanceBytes)
	}
	return string(encoded), nil
}

func normalizeApprover(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: approver is required", ErrInvalid)
	}
	if len(value) > maxApproverBytes {
		return "", fmt.Errorf("%w: approver exceeds %d bytes", ErrInvalid, maxApproverBytes)
	}
	if err := checkText("approver", value, maxApproverBytes, false); err != nil {
		return "", err
	}
	return value, nil
}

func RewriteRuleAction(ruleJSON, action string) (string, error) {
	compiled, err := intel.DecodeCompiledRule([]byte(ruleJSON))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	compiled.Rule.Action = action
	if err := intel.ValidateCompiledRule(compiled); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	encoded, err := json.Marshal(compiled)
	if err != nil {
		return "", fmt.Errorf("%w: encode rule: %v", ErrInvalid, err)
	}
	if len(encoded) > maxRuleJSONBytes {
		return "", fmt.Errorf("%w: rule_json exceeds %d bytes", ErrInvalid, maxRuleJSONBytes)
	}
	return string(encoded), nil
}
