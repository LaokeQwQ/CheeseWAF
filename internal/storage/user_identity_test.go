package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
)

func TestSQLiteUserWritesRejectInvalidUsernames(t *testing.T) {
	for _, username := range []string{"", "ab", " admin ", "admin ", "ad min", "ad\tmin", "admin\n", "ad\x00min", "ad\u200bmin", "admin\u00a0", "admin-", "1admin", strings.Repeat("a", 33)} {
		t.Run(username, func(t *testing.T) {
			t.Parallel()
			store := identityTestStore(t)
			ctx := context.Background()
			original := &User{ID: "canonical-id", Username: "admin", PasswordHash: "original-hash", Role: "admin"}
			if err := store.CreateUser(ctx, original); err != nil {
				t.Fatal(err)
			}

			candidate := &User{Username: username, PasswordHash: "candidate-hash"}
			before := *candidate
			if err := store.CreateUser(ctx, candidate); !errors.Is(err, identity.ErrInvalidUsername) {
				t.Errorf("CreateUser(%q) error = %v, want ErrInvalidUsername", username, err)
			}
			if *candidate != before {
				t.Errorf("rejected create mutated its input: before=%+v after=%+v", before, candidate)
			}

			update := *original
			update.Username = username
			update.PasswordHash = "changed-hash"
			update.Role = "readonly"
			before = update
			if err := store.UpdateUser(ctx, &update); !errors.Is(err, identity.ErrInvalidUsername) {
				t.Errorf("UpdateUser(%q) error = %v, want ErrInvalidUsername", username, err)
			}
			if update != before {
				t.Errorf("rejected update mutated its input: before=%+v after=%+v", before, update)
			}
			users, err := store.ListUsers(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(users) != 1 || users[0] != *original {
				t.Fatalf("invalid writes changed stored users: %+v", users)
			}
		})
	}
}

func TestSQLiteUserWritesPreserveCanonicalUsernames(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	user := &User{Username: "Cheese.Admin_1", PasswordHash: "hash", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	created, err := store.GetUserByUsername(ctx, "Cheese.Admin_1")
	if err != nil || created == nil || created.Username != user.Username {
		t.Fatalf("canonical create changed username: user=%+v err=%v", created, err)
	}
	user.Username = "New.Admin_2"
	if err := store.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	updated, err := store.GetUserByUsername(ctx, "New.Admin_2")
	if err != nil || updated == nil || updated.Username != user.Username || updated.ID != user.ID {
		t.Fatalf("canonical update changed identity: user=%+v err=%v", updated, err)
	}
}

func TestSQLiteUserWritesRejectNilUser(t *testing.T) {
	store := identityTestStore(t)
	if err := store.CreateUser(context.Background(), nil); err == nil {
		t.Fatal("CreateUser(nil) must return an error")
	}
	if err := store.UpdateUser(context.Background(), nil); err == nil {
		t.Fatal("UpdateUser(nil) must return an error")
	}
}

func TestSQLiteUpdateUserRevokesOnlyTargetSessions(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	first := &User{ID: "first-id", Username: "first-user", PasswordHash: "old", Role: "admin"}
	second := &User{ID: "second-id", Username: "second-user", PasswordHash: "old", Role: "admin"}
	for _, user := range []*User{first, second} {
		if err := store.CreateUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		if err := store.CreateSession(ctx, &Session{ID: user.ID + "-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	first.PasswordHash = "new"
	if err := store.UpdateUser(ctx, first); err != nil {
		t.Fatal(err)
	}
	active, err := store.IsSessionActive(ctx, "first-id-session", first.ID, now.Add(time.Minute))
	if err != nil || active {
		t.Fatalf("target session active=%v err=%v", active, err)
	}
	active, err = store.IsSessionActive(ctx, "second-id-session", second.ID, now.Add(time.Minute))
	if err != nil || !active {
		t.Fatalf("unrelated session active=%v err=%v", active, err)
	}
}

func TestSQLiteUpdateUserRollsBackWhenSessionRevocationFails(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	user := &User{ID: "rollback-id", Username: "rollback-user", PasswordHash: "old", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	original := *user
	if err := store.CreateSession(ctx, &Session{ID: "rollback-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "CREATE TRIGGER fail_security_session BEFORE UPDATE OF revoked_at ON admin_sessions BEGIN SELECT RAISE(ABORT, 'session failure'); END"); err != nil {
		t.Fatal(err)
	}
	update := original
	update.PasswordHash = "new"
	if err := store.UpdateUser(ctx, &update); err == nil {
		t.Fatal("expected session revocation failure")
	}
	stored, err := store.GetUserByID(ctx, user.ID)
	if err != nil || stored == nil || stored.PasswordHash != original.PasswordHash || !stored.UpdatedAt.Equal(original.UpdatedAt) {
		t.Fatalf("user changed after rollback: user=%+v err=%v", stored, err)
	}
	active, err := store.IsSessionActive(ctx, "rollback-session", user.ID, now.Add(time.Minute))
	if err != nil || !active {
		t.Fatalf("session changed after rollback: active=%v err=%v", active, err)
	}
	if !update.UpdatedAt.Equal(original.UpdatedAt) {
		t.Fatalf("failed update mutated input timestamp: before=%v after=%v", original.UpdatedAt, update.UpdatedAt)
	}
}

func TestSQLiteUpdateUserCannotRepairHistoricalUsername(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, "INSERT INTO users(id,username,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?,?)", "dirty-id", " admin ", "old", "admin", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	update := &User{ID: "dirty-id", Username: "recovered-admin", PasswordHash: "new", Role: "admin"}
	if err := store.UpdateUser(ctx, update); !errors.Is(err, identity.ErrInvalidUsername) {
		t.Fatalf("ordinary update repaired dirty username: %v", err)
	}
	stored, err := store.GetUserByID(ctx, "dirty-id")
	if err != nil || stored == nil || stored.Username != " admin " || stored.PasswordHash != "old" {
		t.Fatalf("dirty user changed: user=%+v err=%v", stored, err)
	}
}

func TestSQLiteMigratePreservesHistoricalInvalidUsernames(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	for id, username := range map[string]string{"dirty-id": " admin ", "canonical-id": "admin"} {
		if _, err := store.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,created_at,updated_at) VALUES(?,?,?,'admin',?,?)`, id, username, "hash", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	users, err := store.ListUsers(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("migration merged historical users: users=%+v err=%v", users, err)
	}
	for id, username := range map[string]string{"dirty-id": " admin ", "canonical-id": "admin"} {
		user, err := store.GetUserByID(ctx, id)
		if err != nil || user == nil || user.Username != username {
			t.Fatalf("migration changed %q: user=%+v err=%v", id, user, err)
		}
	}
	user, err := store.GetUserByID(ctx, "dirty-id")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateUser(ctx, user); !errors.Is(err, identity.ErrInvalidUsername) {
		t.Fatalf("ordinary UpdateUser accepted historical invalid identity: %v", err)
	}
}

func TestSQLiteRepairUserUsernameRejectsInvalidAuditActor(t *testing.T) {
	for _, actor := range []string{"", " ", " operator", "operator ", "op erator", "operator\n", "op\u200berator", "op\u2060erator", "op\ufefferator"} {
		t.Run(actor, func(t *testing.T) {
			t.Parallel()
			store := identityTestStore(t)
			ctx := context.Background()
			if _, err := store.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES('dirty-id',' admin ','hash','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RepairUserUsername(ctx, "dirty-id", "fixed", actor, "repair"); err == nil || !strings.Contains(err.Error(), "actor") {
				t.Fatalf("repair with actor %q error = %v, want actor validation error", actor, err)
			}
			user, err := store.GetUserByID(ctx, "dirty-id")
			if err != nil || user == nil || user.Username != " admin " {
				t.Fatalf("invalid actor changed the dirty user: user=%+v err=%v", user, err)
			}
			var auditCount int
			if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_username_repairs`).Scan(&auditCount); err != nil || auditCount != 0 {
				t.Fatalf("invalid actor produced a success audit: count=%d err=%v", auditCount, err)
			}
		})
	}
}

func TestSQLiteRepairUserUsernameRejectsInvalidUserID(t *testing.T) {
	for _, userID := range []string{"", " ", " dirty-id", "dirty-id ", "dirty\nid", "dirty\u200bid", "dirty\u2060id", "dirty\ufeffid"} {
		t.Run(userID, func(t *testing.T) {
			t.Parallel()
			store := identityTestStore(t)
			if _, err := store.RepairUserUsername(context.Background(), userID, "fixed", "os-user:501", "repair"); err == nil || !strings.Contains(err.Error(), "user ID must") {
				t.Fatalf("repair with user ID %q error = %v, want ID validation error", userID, err)
			}
		})
	}
}

func TestSQLiteRepairUserUsernameValidatesAuditReasonWithoutRewriting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reason string
	}{
		{name: "empty", reason: " "},
		{name: "newline", reason: "operator\nreason"},
		{name: "zero width", reason: "operator\u2060reason"},
		{name: "invalid utf8", reason: string([]byte{0xff, 0xfe})},
		{name: "too long", reason: strings.Repeat("x", 513)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := identityTestStore(t)
			if _, err := store.db.ExecContext(context.Background(), `INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES('dirty-id',' admin ','hash','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			if _, err := store.RepairUserUsername(context.Background(), "dirty-id", "fixed", "os-user:501", tc.reason); err == nil || !strings.Contains(err.Error(), "reason") {
				t.Fatalf("repair reason %q error = %v, want validation error", tc.reason, err)
			}
			user, err := store.GetUserByID(context.Background(), "dirty-id")
			if err != nil || user == nil || user.Username != " admin " {
				t.Fatalf("invalid reason changed user: user=%+v err=%v", user, err)
			}
		})
	}

	store := identityTestStore(t)
	if _, err := store.db.ExecContext(context.Background(), `INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES('dirty-id',' admin ','hash','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	const reason = "人工修复历史账号"
	if _, err := store.RepairUserUsername(context.Background(), "dirty-id", "fixed", "os-user:501", reason); err != nil {
		t.Fatalf("valid Unicode reason rejected: %v", err)
	}
	var stored string
	if err := store.db.QueryRowContext(context.Background(), `SELECT reason FROM user_username_repairs WHERE user_id='dirty-id'`).Scan(&stored); err != nil || stored != reason {
		t.Fatalf("reason was rewritten: stored=%q err=%v", stored, err)
	}
}

func TestSQLiteRepairUserUsernameAuditIsAppendOnly(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,created_at,updated_at) VALUES('dirty-id',' admin ','hash','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	repair, err := store.RepairUserUsername(ctx, "dirty-id", "fixed", "os-user:501", "repair")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE user_username_repairs SET reason='changed' WHERE id=?`,
		`DELETE FROM user_username_repairs WHERE id=?`,
		`INSERT OR REPLACE INTO user_username_repairs(id,user_id,old_username,new_username,actor,reason,revoked_sessions,created_at) VALUES(?,?,?,?,?,?,?,?)`,
	} {
		args := []any{repair.ID}
		if strings.HasPrefix(query, "INSERT OR REPLACE") {
			args = []any{repair.ID, repair.UserID, repair.OldUsername, repair.NewUsername, repair.Actor, "changed", repair.RevokedSessions, formatTime(repair.CreatedAt)}
		}
		if _, err := store.db.ExecContext(ctx, query, args...); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("audit mutation was not rejected: query=%q err=%v", query, err)
		}
	}
	var oldName, newName, reason string
	if err := store.db.QueryRowContext(ctx, `SELECT old_username,new_username,reason FROM user_username_repairs WHERE id=?`, repair.ID).Scan(&oldName, &newName, &reason); err != nil || oldName != " admin " || newName != "fixed" || reason != "repair" {
		t.Fatalf("audit record changed: old=%q new=%q reason=%q err=%v", oldName, newName, reason, err)
	}
}

func identityTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}
