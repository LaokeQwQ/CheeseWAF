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

func scanNotification(row scanner) (*storage.Notification, error) {
	var v storage.Notification
	var read, pinned dbBool
	var created, updated dbTime
	if e := row.Scan(&v.ID, &v.UserID, &v.Type, &v.Title, &v.Message, &v.Target, &read, &pinned, &created, &updated); e != nil {
		return nil, e
	}
	v.Read, v.Pinned = bool(read), bool(pinned)
	v.CreatedAt = created.Time
	v.UpdatedAt = updated.Time
	return &v, nil
}
func (s *Store) CreateNotification(ctx context.Context, v *storage.Notification) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrInvalidStore
	}
	if v == nil || strings.TrimSpace(v.UserID) == "" || strings.TrimSpace(v.Title) == "" {
		return errors.New("notification user id and title are required")
	}
	if v.ID == "" {
		v.ID = uuid.NewString()
	}
	switch strings.ToLower(strings.TrimSpace(v.Type)) {
	case "critical", "warning":
		v.Type = strings.ToLower(strings.TrimSpace(v.Type))
	default:
		v.Type = "info"
	}
	now := time.Now().UTC()
	if v.CreatedAt.IsZero() {
		v.CreatedAt = now
	}
	if v.UpdatedAt.IsZero() {
		v.UpdatedAt = now
	}
	_, e := s.exec(ctx, "INSERT INTO notifications(id,user_id,type,title,message,target,is_read,is_pinned,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING", v.ID, v.UserID, v.Type, v.Title, v.Message, v.Target, v.Read, v.Pinned, v.CreatedAt, v.UpdatedAt)
	return e
}
func (s *Store) ListNotifications(ctx context.Context, userID string, f storage.NotificationFilter) ([]storage.Notification, int64, int64, int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, 0, 0, 0, ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" {
		return nil, 0, 0, 0, errors.New("notification user id is required")
	}
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 20
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := "user_id=?"
	args := []any{userID}
	switch strings.ToLower(strings.TrimSpace(f.State)) {
	case "", "all":
	case "unread":
		where += " AND is_read=FALSE"
	case "read":
		where += " AND is_read=TRUE"
	case "pinned":
		where += " AND is_pinned=TRUE"
	default:
		return nil, 0, 0, 0, errors.New("invalid notification filter")
	}
	var total, unread, filtered int64
	if e := s.row(ctx, "SELECT COUNT(1),COALESCE(SUM(CASE WHEN is_read=FALSE THEN 1 ELSE 0 END),0) FROM notifications WHERE user_id=?", userID).Scan(&total, &unread); e != nil {
		return nil, 0, 0, 0, e
	}
	if e := s.row(ctx, "SELECT COUNT(1) FROM notifications WHERE "+where, args...).Scan(&filtered); e != nil {
		return nil, 0, 0, 0, e
	}
	qargs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, e := s.query(ctx, "SELECT id,user_id,type,title,message,target,is_read,is_pinned,created_at,updated_at FROM notifications WHERE "+where+" ORDER BY is_pinned DESC,created_at DESC,id DESC LIMIT ? OFFSET ?", qargs...)
	if e != nil {
		return nil, 0, 0, 0, e
	}
	defer rows.Close()
	out := make([]storage.Notification, 0, f.Limit)
	for rows.Next() {
		v, e := scanNotification(rows)
		if e != nil {
			return nil, 0, 0, 0, e
		}
		out = append(out, *v)
	}
	return out, total, filtered, unread, rows.Err()
}
func (s *Store) UpdateNotification(ctx context.Context, userID, id string, p storage.NotificationPatch) (*storage.Notification, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(id) == "" {
		return nil, errors.New("notification user id and id are required")
	}
	if p.Read == nil && p.Pinned == nil {
		return nil, errors.New("notification patch is empty")
	}
	sets := []string{"updated_at=?"}
	args := []any{time.Now().UTC()}
	if p.Read != nil {
		sets = append(sets, "is_read=?")
		args = append(args, *p.Read)
	}
	if p.Pinned != nil {
		sets = append(sets, "is_pinned=?")
		args = append(args, *p.Pinned)
	}
	args = append(args, id, userID)
	res, e := s.exec(ctx, "UPDATE notifications SET "+strings.Join(sets, ",")+" WHERE id=? AND user_id=?", args...)
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
	v, e := scanNotification(s.row(ctx, "SELECT id,user_id,type,title,message,target,is_read,is_pinned,created_at,updated_at FROM notifications WHERE id=? AND user_id=?", id, userID))
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return v, e
}
func (s *Store) MarkAllNotificationsRead(ctx context.Context, userID string) (int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" {
		return 0, errors.New("notification user id is required")
	}
	res, e := s.exec(ctx, "UPDATE notifications SET is_read=TRUE,updated_at=? WHERE user_id=? AND is_read=FALSE", time.Now().UTC(), userID)
	if e != nil {
		return 0, e
	}
	return res.RowsAffected()
}
func (s *Store) ClearNotifications(ctx context.Context, userID string) (int64, error) {
	if s == nil || s.db == nil || ctx == nil {
		return 0, ErrInvalidStore
	}
	if strings.TrimSpace(userID) == "" {
		return 0, errors.New("notification user id is required")
	}
	res, e := s.exec(ctx, "DELETE FROM notifications WHERE user_id=?", userID)
	if e != nil {
		return 0, e
	}
	return res.RowsAffected()
}
