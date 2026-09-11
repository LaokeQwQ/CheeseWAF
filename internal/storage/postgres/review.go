package postgres

import (
	"context"
	"database/sql"
	"errors"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/google/uuid"
	"strings"
	"time"
)

const reviewColumns = "id,trace_id,site_id,client_ip,method,uri,category,severity,payload,protection_level,shape,source,param_name,fingerprint,status,ai_verdict,decided_by_subject,decided_by_name,decided_by_role,decided_at,decision,applied_rule_id,created_at"

func scanReview(row scanner) (*storage.ReviewItem, error) {
	var v storage.ReviewItem
	var decided, created dbTime
	if e := row.Scan(&v.ID, &v.TraceID, &v.SiteID, &v.ClientIP, &v.Method, &v.URI, &v.Category, &v.Severity, &v.Payload, &v.ProtectionLevel, &v.Shape, &v.Source, &v.ParamName, &v.Fingerprint, &v.Status, &v.AIVerdict, &v.DecidedBySubject, &v.DecidedByName, &v.DecidedByRole, &decided, &v.Decision, &v.AppliedRuleID, &created); e != nil {
		return nil, e
	}
	v.DecidedAt = decided.Time
	v.CreatedAt = created.Time
	return &v, nil
}
func (s *Store) CreateReviewItem(ctx context.Context, v *storage.ReviewItem) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil {
		return errors.New("review item is required")
	}
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	if v.Status == "" {
		v.Status = "pending"
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	if len(v.Payload) > 2000 {
		v.Payload = v.Payload[:2000]
	}
	_, e := s.exec(ctx, "INSERT INTO review_items("+reviewColumns+") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.TraceID, v.SiteID, v.ClientIP, v.Method, v.URI, v.Category, v.Severity, v.Payload, v.ProtectionLevel, v.Shape, v.Source, v.ParamName, v.Fingerprint, v.Status, v.AIVerdict, v.DecidedBySubject, v.DecidedByName, v.DecidedByRole, optionalTimestamp(v.DecidedAt), v.Decision, v.AppliedRuleID, v.CreatedAt)
	return e
}
func (s *Store) GetReviewItem(ctx context.Context, id string) (*storage.ReviewItem, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	v, e := scanReview(s.row(ctx, "SELECT "+reviewColumns+" FROM review_items WHERE id=?", id))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return v, e
}
func (s *Store) ListReviewItems(ctx context.Context, f storage.ReviewFilter) ([]storage.ReviewItem, int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, 0, ErrInvalidStore
	}
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where, args := reviewWhere(f)
	var total int64
	if e := s.row(ctx, "SELECT COUNT(1) FROM review_items WHERE "+where, args...).Scan(&total); e != nil {
		return nil, 0, e
	}
	qargs := append(append([]any{}, args...), limit, f.Offset)
	rows, e := s.query(ctx, "SELECT "+reviewColumns+" FROM review_items WHERE "+where+" ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?", qargs...)
	if e != nil {
		return nil, 0, e
	}
	defer rows.Close()
	out := make([]storage.ReviewItem, 0, limit)
	for rows.Next() {
		v, e := scanReview(rows)
		if e != nil {
			return nil, 0, e
		}
		out = append(out, *v)
	}
	return out, total, rows.Err()
}
func (s *Store) HasPendingReview(ctx context.Context, siteID, category, payload, uri string) (bool, error) {
	return s.hasReview(ctx, siteID, category, payload, uri, true)
}
func (s *Store) HasSimilarReview(ctx context.Context, siteID, category, payload, uri string) (bool, error) {
	return s.hasReview(ctx, siteID, category, payload, uri, false)
}
func (s *Store) hasReview(ctx context.Context, siteID, category, payload, uri string, pending bool) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, ErrInvalidStore
	}
	q := "SELECT EXISTS(SELECT 1 FROM review_items WHERE site_id=? AND category=? AND payload=? AND uri=?"
	if pending {
		q += " AND status='pending'"
	}
	q += ")"
	var found bool
	e := s.row(ctx, q, siteID, category, payload, uri).Scan(&found)
	return found, e
}
func (s *Store) PruneReviewItems(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, ErrInvalidStore
	}
	if before.IsZero() {
		before = time.Now().UTC()
	}
	if batchSize <= 0 || batchSize > 500 {
		batchSize = 500
	}
	res, e := s.exec(ctx, "WITH doomed AS (SELECT id FROM review_items WHERE status <> 'pending' AND created_at < ? ORDER BY created_at,id LIMIT ?) DELETE FROM review_items r USING doomed d WHERE r.id=d.id", before, batchSize)
	if e != nil {
		return 0, e
	}
	return res.RowsAffected()
}
func (s *Store) SetReviewAIVerdict(ctx context.Context, id, verdict string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("review id is required")
	}
	if len(verdict) > 2000 {
		verdict = verdict[:2000]
	}
	_, e := s.exec(ctx, "UPDATE review_items SET ai_verdict=? WHERE id=?", verdict, id)
	return e
}
func (s *Store) ClaimReviewItem(ctx context.Context, id, decision string) (*storage.ReviewDecisionClaim, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(decision) == "" {
		return nil, errors.New("review decision claim is required")
	}
	token := uuid.NewString()
	res, e := s.exec(ctx, "UPDATE review_items SET decision_claim=? WHERE id=? AND decision_claim='' AND (status='pending' OR (status='blocked' AND ? IN ('block_payload','block_uri','block_ip','block_fingerprint') AND COALESCE(decision,'') <> ?))", token, id, decision, decision)
	if e != nil {
		return nil, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return nil, e
	}
	if n == 0 {
		return nil, nil
	}
	item, e := s.GetReviewItem(ctx, id)
	if e != nil {
		return nil, e
	}
	if item == nil {
		return nil, errors.New("review item disappeared after claim")
	}
	return &storage.ReviewDecisionClaim{Item: item, Token: token}, nil
}
func (s *Store) ReleaseReviewItem(ctx context.Context, id, token string) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(token) == "" {
		return errors.New("review decision claim is required")
	}
	res, e := s.exec(ctx, "UPDATE review_items SET decision_claim='' WHERE id=? AND decision_claim=?", id, token)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		return errors.New("review decision claim was lost")
	}
	return nil
}
func decisionStatus(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "allow") || strings.EqualFold(strings.TrimSpace(v), "allow_whitelist") {
		return "allowed"
	}
	return "blocked"
}
func (s *Store) CompleteReviewItem(ctx context.Context, id, token string, d storage.ReviewDecision) (*storage.ReviewItem, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(token) == "" || strings.TrimSpace(d.Decision) == "" {
		return nil, errors.New("review decision completion is required")
	}
	res, e := s.exec(ctx, "UPDATE review_items SET status=?,decision=?,applied_rule_id=?,decided_by_subject=?,decided_by_name=?,decided_by_role=?,decided_at=?,decision_claim='' WHERE id=? AND decision_claim=?", decisionStatus(d.Decision), d.Decision, d.AppliedRuleID, d.DecidedBySubject, d.DecidedByName, d.DecidedByRole, time.Now().UTC(), id, token)
	if e != nil {
		return nil, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return nil, e
	}
	if n == 0 {
		return nil, nil
	}
	return s.GetReviewItem(ctx, id)
}
func (s *Store) DecideReviewItem(ctx context.Context, id string, d storage.ReviewDecision) (*storage.ReviewItem, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(d.Decision) == "" {
		return nil, errors.New("review decision is required")
	}
	res, e := s.exec(ctx, "UPDATE review_items SET status=?,decision=?,applied_rule_id=?,decided_by_subject=?,decided_by_name=?,decided_by_role=?,decided_at=? WHERE id=? AND decision_claim='' AND (status='pending' OR (status='blocked' AND ? IN ('block_payload','block_uri','block_ip','block_fingerprint') AND COALESCE(decision,'') <> ?))", decisionStatus(d.Decision), d.Decision, d.AppliedRuleID, d.DecidedBySubject, d.DecidedByName, d.DecidedByRole, time.Now().UTC(), id, d.Decision, d.Decision)
	if e != nil {
		return nil, e
	}
	n, e := res.RowsAffected()
	if e != nil {
		return nil, e
	}
	if n == 0 {
		return nil, nil
	}
	return s.GetReviewItem(ctx, id)
}
func escapeLike(v string) string {
	v = strings.ReplaceAll(v, "\\", "\\\\")
	v = strings.ReplaceAll(v, "%", "\\%")
	v = strings.ReplaceAll(v, "_", "\\_")
	return v
}
func reviewWhere(f storage.ReviewFilter) (string, []any) {
	c := []string{"TRUE"}
	var a []any
	if v := strings.TrimSpace(f.SiteID); v != "" {
		c = append(c, "site_id=?")
		a = append(a, v)
	}
	if v := strings.TrimSpace(f.Category); v != "" {
		c = append(c, "category=?")
		a = append(a, v)
	}
	if v := strings.TrimSpace(f.Status); v != "" {
		c = append(c, "status=?")
		a = append(a, v)
	}
	if !f.Start.IsZero() {
		c = append(c, "created_at>=?")
		a = append(a, f.Start.UTC())
	}
	if !f.End.IsZero() {
		c = append(c, "created_at<=?")
		a = append(a, f.End.UTC())
	}
	if v := strings.TrimSpace(f.Search); v != "" {
		c = append(c, "LOWER(CONCAT_WS(' ',id,trace_id,site_id,client_ip,method,uri,category,severity,payload,status,source,param_name,fingerprint,ai_verdict,decision,applied_rule_id,decided_by_name)) LIKE LOWER(?) ESCAPE '\\\\'")
		a = append(a, "%"+escapeLike(v)+"%")
	}
	add := func(t time.Time, id, op string) {
		if !t.IsZero() && id != "" {
			c = append(c, "(created_at"+op+"? OR (created_at=? AND id"+op+"?))")
			a = append(a, t.UTC(), t.UTC(), id)
		} else if !t.IsZero() {
			c = append(c, "created_at"+op+"?")
			a = append(a, t.UTC())
		} else if id != "" {
			c = append(c, "id"+op+"?")
			a = append(a, id)
		}
	}
	if !f.WatermarkTime.IsZero() || f.WatermarkID != "" {
		add(f.WatermarkTime, f.WatermarkID, "<")
	} else if !f.BeforeTime.IsZero() || f.BeforeID != "" {
		add(f.BeforeTime, f.BeforeID, "<")
	} else if !f.AfterTime.IsZero() || f.AfterID != "" {
		add(f.AfterTime, f.AfterID, ">")
	}
	return strings.Join(c, " AND "), a
}
