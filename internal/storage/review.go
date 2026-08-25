package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const reviewCreatedAtKeySQL = `(CASE
	WHEN instr(created_at, '.') = 0 THEN substr(created_at, 1, 19) || '.000000000Z'
	ELSE substr(created_at, 1, instr(created_at, '.')) || substr(substr(created_at, instr(created_at, '.') + 1, length(created_at) - instr(created_at, '.') - 1) || '000000000', 1, 9) || 'Z'
	END)`

func (s *SQLiteStore) CreateReviewItem(ctx context.Context, item *ReviewItem) error {
	if item == nil {
		return fmt.Errorf("review item is required")
	}
	if item.ID == "" {
		item.ID = uuid.NewString()
	}
	if item.Status == "" {
		item.Status = "pending"
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	if len(item.Payload) > 2000 {
		item.Payload = item.Payload[:2000]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO review_items(
		id,trace_id,site_id,client_ip,method,uri,category,severity,payload,
		protection_level,shape,source,param_name,fingerprint,status,ai_verdict,decided_by_subject,decided_by_name,
		decided_by_role,decided_at,decision,applied_rule_id,created_at
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		item.ID, item.TraceID, item.SiteID, item.ClientIP, item.Method, item.URI, item.Category, item.Severity, item.Payload,
		item.ProtectionLevel, item.Shape, item.Source, item.ParamName, item.Fingerprint, item.Status, item.AIVerdict, item.DecidedBySubject, item.DecidedByName,
		item.DecidedByRole, formatReviewTime(item.DecidedAt), item.Decision, item.AppliedRuleID, formatTime(item.CreatedAt))
	return err
}

func (s *SQLiteStore) GetReviewItem(ctx context.Context, id string) (*ReviewItem, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,trace_id,site_id,client_ip,method,uri,category,severity,payload,
		protection_level,shape,source,param_name,fingerprint,status,ai_verdict,decided_by_subject,decided_by_name,decided_by_role,
		decided_at,decision,applied_rule_id,created_at FROM review_items WHERE id=?`, id)
	item, err := scanReviewItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return item, err
}

func (s *SQLiteStore) ListReviewItems(ctx context.Context, filter ReviewFilter) ([]ReviewItem, int64, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	filter.Limit = limit
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	where, args := reviewWhere(filter)
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM review_items WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append(append([]any(nil), args...), limit, filter.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT id,trace_id,site_id,client_ip,method,uri,category,severity,payload,
		protection_level,shape,source,param_name,fingerprint,status,ai_verdict,decided_by_subject,decided_by_name,decided_by_role,
		decided_at,decision,applied_rule_id,created_at FROM review_items WHERE `+where+` ORDER BY `+reviewCreatedAtKeySQL+` DESC, id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	// Capacity is a fixed bound, not the request limit, so allocation size is not caller-controlled.
	items := make([]ReviewItem, 0, 20)
	for rows.Next() {
		item, err := scanReviewItem(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, *item)
	}
	return items, total, rows.Err()
}

func (s *SQLiteStore) HasPendingReview(ctx context.Context, siteID, category, payload, uri string) (bool, error) {
	return s.hasReview(ctx, siteID, category, payload, uri, true)
}

func (s *SQLiteStore) HasSimilarReview(ctx context.Context, siteID, category, payload, uri string) (bool, error) {
	return s.hasReview(ctx, siteID, category, payload, uri, false)
}

// PruneReviewItems removes only old, terminal review items. Pending items are
// retained regardless of age so a delayed operator or model can still inspect
// them. The batch limit keeps each maintenance transaction short.
func (s *SQLiteStore) PruneReviewItems(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	if batchSize <= 0 || batchSize > defaultReviewPruneBatch {
		batchSize = defaultReviewPruneBatch
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM review_items WHERE id IN (
		SELECT id FROM review_items WHERE status <> 'pending' AND created_at < ? ORDER BY created_at LIMIT ?
	)`, formatTime(before.UTC()), batchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *SQLiteStore) hasReview(ctx context.Context, siteID, category, payload, uri string, pendingOnly bool) (bool, error) {
	query := `SELECT COUNT(1) FROM review_items WHERE site_id=? AND category=? AND payload=? AND uri=?`
	if pendingOnly {
		query += ` AND status='pending'`
	}
	var n int
	err := s.db.QueryRowContext(ctx, query, siteID, category, payload, uri).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *SQLiteStore) SetReviewAIVerdict(ctx context.Context, id, verdict string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("review id is required")
	}
	if len(verdict) > 2000 {
		verdict = verdict[:2000]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE review_items SET ai_verdict=? WHERE id=?`, verdict, id)
	return err
}

func (s *SQLiteStore) DecideReviewItem(ctx context.Context, id string, decision ReviewDecision) (*ReviewItem, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(decision.Decision) == "" {
		return nil, fmt.Errorf("review decision is required")
	}
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `UPDATE review_items SET status=?, decision=?, applied_rule_id=?,
		decided_by_subject=?, decided_by_name=?, decided_by_role=?, decided_at=?
		WHERE id=? AND (status='pending' OR (status='blocked' AND ? IN ('block_payload','block_uri','block_ip','block_fingerprint')))`,
		reviewStatusForDecision(decision.Decision), decision.Decision, decision.AppliedRuleID,
		decision.DecidedBySubject, decision.DecidedByName, decision.DecidedByRole, formatTime(now), id, decision.Decision)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, nil
	}
	return s.GetReviewItem(ctx, id)
}

func reviewStatusForDecision(decision string) string {
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "allow", "allow_whitelist":
		return "allowed"
	default:
		return "blocked"
	}
}

func reviewWhere(filter ReviewFilter) (string, []any) {
	clauses := []string{"1=1"}
	var args []any
	if site := strings.TrimSpace(filter.SiteID); site != "" {
		clauses = append(clauses, "site_id=?")
		args = append(args, site)
	}
	if cat := strings.TrimSpace(filter.Category); cat != "" {
		clauses = append(clauses, "category=?")
		args = append(args, cat)
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		clauses = append(clauses, "status=?")
		args = append(args, status)
	}
	if !filter.Start.IsZero() {
		clauses = append(clauses, reviewCreatedAtKeySQL+">=?")
		args = append(args, formatReviewKeyTime(filter.Start))
	}
	if !filter.End.IsZero() {
		clauses = append(clauses, reviewCreatedAtKeySQL+"<=?")
		args = append(args, formatReviewKeyTime(filter.End))
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		pattern := "%" + escapeLike(search) + "%"
		clauses = append(clauses, `LOWER(COALESCE(id,'') || ' ' || COALESCE(trace_id,'') || ' ' || COALESCE(site_id,'') || ' ' || COALESCE(client_ip,'') || ' ' || COALESCE(method,'') || ' ' || COALESCE(uri,'') || ' ' || COALESCE(category,'') || ' ' || COALESCE(severity,'') || ' ' || COALESCE(payload,'') || ' ' || COALESCE(status,'') || ' ' || COALESCE(source,'') || ' ' || COALESCE(param_name,'') || ' ' || COALESCE(fingerprint,'') || ' ' || COALESCE(ai_verdict,'') || ' ' || COALESCE(decision,'') || ' ' || COALESCE(applied_rule_id,'') || ' ' || COALESCE(decided_by_name,'')) LIKE LOWER(?) ESCAPE '\'`)
		args = append(args, pattern)
	}
	if !filter.WatermarkTime.IsZero() {
		clause, cursorArgs := reviewKeysetClause(filter.WatermarkTime, filter.WatermarkID, "<")
		clauses = append(clauses, clause)
		args = append(args, cursorArgs...)
	} else if filter.WatermarkID != "" {
		clauses = append(clauses, "id<?")
		args = append(args, filter.WatermarkID)
	}
	if !filter.BeforeTime.IsZero() {
		clause, cursorArgs := reviewKeysetClause(filter.BeforeTime, filter.BeforeID, "<")
		clauses = append(clauses, clause)
		args = append(args, cursorArgs...)
	} else if filter.BeforeID != "" {
		clauses = append(clauses, "id<?")
		args = append(args, filter.BeforeID)
	}
	if !filter.AfterTime.IsZero() {
		clause, cursorArgs := reviewKeysetClause(filter.AfterTime, filter.AfterID, ">")
		clauses = append(clauses, clause)
		args = append(args, cursorArgs...)
	} else if filter.AfterID != "" {
		clauses = append(clauses, "id>?")
		args = append(args, filter.AfterID)
	}
	return strings.Join(clauses, " AND "), args
}

func formatReviewKeyTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func reviewKeysetClause(timestamp time.Time, id, direction string) (string, []any) {
	if timestamp.IsZero() {
		return "id" + direction + "?", []any{id}
	}
	stamp := formatReviewKeyTime(timestamp)
	if id == "" {
		return reviewCreatedAtKeySQL + direction + "?", []any{stamp}
	}
	return "(" + reviewCreatedAtKeySQL + direction + "? OR (" + reviewCreatedAtKeySQL + "=? AND id" + direction + "?))", []any{stamp, stamp, id}
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "%", `\%`)
	value = strings.ReplaceAll(value, "_", `\_`)
	return value
}

func formatReviewTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return formatTime(t)
}

func scanReviewItem(row scanner) (*ReviewItem, error) {
	var item ReviewItem
	var decidedAt, createdAt string
	if err := row.Scan(
		&item.ID, &item.TraceID, &item.SiteID, &item.ClientIP, &item.Method, &item.URI, &item.Category, &item.Severity, &item.Payload,
		&item.ProtectionLevel, &item.Shape, &item.Source, &item.ParamName, &item.Fingerprint, &item.Status, &item.AIVerdict, &item.DecidedBySubject, &item.DecidedByName, &item.DecidedByRole,
		&decidedAt, &item.Decision, &item.AppliedRuleID, &createdAt,
	); err != nil {
		return nil, err
	}
	if decidedAt != "" {
		item.DecidedAt = parseTime(decidedAt)
	}
	item.CreatedAt = parseTime(createdAt)
	return &item, nil
}
