package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func TestCLISQLitePathFollowsEffectiveDataDir(t *testing.T) {
	originalConfigPath := configPath
	originalDataDir := dataDir
	t.Cleanup(func() {
		configPath = originalConfigPath
		dataDir = originalDataDir
	})

	root := t.TempDir()
	configPath = filepath.Join(root, "config", "cheesewaf.yaml")
	dataDir = filepath.Join(root, "runtime")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	cfg := config.Default()
	cfg.Setup.DataDir = "./data"
	cfg.Setup.RuntimeDir = "./data/run"
	cfg.Storage.SQLite.Path = "./data/cheesewaf.db"
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save test config: %v", err)
	}

	got, err := cliSQLitePath()
	if err != nil {
		t.Fatalf("cliSQLitePath() error = %v", err)
	}
	want := filepath.Join(dataDir, "cheesewaf.db")
	if got != want {
		t.Fatalf("cliSQLitePath() = %q, want %q", got, want)
	}
}

func TestChangeUserPasswordPreserves2FAByDefault(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	user := seedPasswordTestUser(t, store, "admin", "old-password-123")
	user.TwoFAEnabled = true
	user.TwoFASecret = "SECRET"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("enable test 2fa: %v", err)
	}
	now := time.Now().UTC()
	session := &storage.Session{ID: "password-reset-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "N7v!mKq2PxR",
	}); err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}

	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("N7v!mKq2PxR")) != nil {
		t.Fatal("updated password hash does not match new password")
	}
	if !updated.TwoFAEnabled || updated.TwoFASecret != "SECRET" {
		t.Fatalf("password reset must preserve 2FA, got enabled=%v secret=%q", updated.TwoFAEnabled, updated.TwoFASecret)
	}
	active, err := store.IsSessionActive(context.Background(), session.ID, user.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("check reset session: %v", err)
	}
	if active {
		t.Fatal("password reset must revoke existing sessions")
	}
}

func TestChangeUserPasswordReset2FAWhenRequested(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	user := seedPasswordTestUser(t, store, "admin", "old-password-123")
	user.TwoFAEnabled = true
	user.TwoFASecret = "SECRET"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("enable test 2fa: %v", err)
	}

	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "N7v!mKq2PxR",
		Reset2FA: true,
	}); err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}

	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if updated.TwoFAEnabled || updated.TwoFASecret != "" {
		t.Fatalf("--reset-2fa should clear 2FA, got enabled=%v secret=%q", updated.TwoFAEnabled, updated.TwoFASecret)
	}
}

func TestChangeUserPasswordFromStdin(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	seedPasswordTestUser(t, store, "admin", "old-password-123")

	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		PasswordStdin: true,
		Input:         bytes.NewBufferString("Std1n!Kq9mX\n"),
	}); err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}

	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte("Std1n!Kq9mX")) != nil {
		t.Fatal("updated password hash does not match stdin password")
	}
}

func TestChangeUserPasswordGenerate(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	seedPasswordTestUser(t, store, "admin", "old-password-123")

	generated, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{Generate: true})
	if err != nil {
		t.Fatalf("changeUserPassword() error = %v", err)
	}
	if len(generated) < 16 || !passwordHasClasses(generated) {
		t.Fatalf("generated password is not strong enough: %q", generated)
	}
	updated, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(updated.PasswordHash), []byte(generated)) != nil {
		t.Fatal("updated password hash does not match generated password")
	}
}

func TestChangeUserPasswordValidation(t *testing.T) {
	t.Parallel()

	_, sqlitePath := userPasswordTestStore(t)
	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "short",
	}); err == nil || !strings.Contains(err.Error(), "at least 10") {
		t.Fatalf("expected short password validation error, got %v", err)
	}
	if _, err := changeUserPassword(context.Background(), sqlitePath, "admin", cliPasswordOptions{
		Password: "valid-password-123",
		Generate: true,
	}); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected source validation error, got %v", err)
	}
}

func TestRenameUserUpdatesUsernameAndRevokesSessions(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	user := seedPasswordTestUser(t, store, "admin", "old-password-123")
	now := time.Now().UTC()
	session := &storage.Session{
		ID:              "session-1",
		UserID:          user.ID,
		Username:        user.Username,
		Role:            user.Role,
		CredentialEpoch: user.CredentialEpoch,
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Hour),
	}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	renamed, err := renameUser(context.Background(), sqlitePath, "admin", "Cheese")
	if err != nil {
		t.Fatalf("renameUser() error = %v", err)
	}
	if renamed.ID != user.ID || renamed.Username != "Cheese" {
		t.Fatalf("unexpected renamed user: %+v", renamed)
	}
	oldUser, err := store.GetUserByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatalf("get old user: %v", err)
	}
	if oldUser != nil {
		t.Fatalf("old username should not resolve, got %+v", oldUser)
	}
	newUser, err := store.GetUserByUsername(context.Background(), "Cheese")
	if err != nil {
		t.Fatalf("get new user: %v", err)
	}
	if newUser == nil || newUser.ID != user.ID {
		t.Fatalf("new username did not resolve original user: %+v", newUser)
	}
	active, err := store.IsSessionActive(context.Background(), session.ID, user.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("check session: %v", err)
	}
	if active {
		t.Fatal("rename should revoke existing user sessions")
	}
}

func TestRenameUserValidation(t *testing.T) {
	t.Parallel()

	store, sqlitePath := userPasswordTestStore(t)
	seedPasswordTestUser(t, store, "admin", "old-password-123")
	seedPasswordTestUser(t, store, "reader", "old-password-123")
	if _, err := renameUser(context.Background(), sqlitePath, "missing", "Cheese"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing user error, got %v", err)
	}
	if _, err := renameUser(context.Background(), sqlitePath, "admin", "xy"); err == nil || !strings.Contains(err.Error(), "at least 3") {
		t.Fatalf("expected short username error, got %v", err)
	}
	if _, err := renameUser(context.Background(), sqlitePath, "admin", "reader"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate username error, got %v", err)
	}
}

func TestEnsureAdminUserCreatesAndRecoversAdministrator(t *testing.T) {
	store, sqlitePath := userPasswordTestStore(t)
	generated, err := ensureAdminUser(context.Background(), sqlitePath, "test-admin", cliPasswordOptions{Password: "Test-Only-Initial-Password!42"})
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	if generated != "" {
		t.Fatalf("unexpected generated password: %q", generated)
	}
	user, err := store.GetUserByUsername(context.Background(), "test-admin")
	if err != nil || user == nil || user.Role != "admin" {
		t.Fatalf("administrator not created correctly: user=%+v err=%v", user, err)
	}
	user.Role = "readonly"
	user.TwoFAEnabled = true
	user.TwoFASecret = "stale-secret"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureAdminUser(context.Background(), sqlitePath, "test-admin", cliPasswordOptions{Password: "Test-Only-Recovery-Password!84"}); err != nil {
		t.Fatalf("recover administrator: %v", err)
	}
	recovered, err := store.GetUserByUsername(context.Background(), "test-admin")
	// Role must be restored to admin; 2FA stays until --reset-2fa is used.
	if err != nil || recovered == nil || recovered.Role != "admin" {
		t.Fatalf("administrator not recovered correctly: user=%+v err=%v", recovered, err)
	}
	if !recovered.TwoFAEnabled || recovered.TwoFASecret != "stale-secret" {
		t.Fatalf("ensure-admin must preserve 2FA without --reset-2fa: user=%+v", recovered)
	}
	if _, err := ensureAdminUser(context.Background(), sqlitePath, "test-admin", cliPasswordOptions{Password: "Test-Only-Recovery-Password!85", Reset2FA: true}); err != nil {
		t.Fatalf("recover with reset-2fa: %v", err)
	}
	cleared, err := store.GetUserByUsername(context.Background(), "test-admin")
	if err != nil || cleared == nil || cleared.TwoFAEnabled || cleared.TwoFASecret != "" {
		t.Fatalf("ensure-admin --reset-2fa should clear 2FA: user=%+v err=%v", cleared, err)
	}
}

func TestUserRepairUsernameCommandPreservesAccountAndAuditsRevocation(t *testing.T) {
	ctx := context.Background()
	store, sqlitePath, db, user := historicalUsernameTestUser(t, " admin ")
	other := seedPasswordTestUser(t, store, "admin", "other-password-123")
	now := time.Now().UTC()
	for _, session := range []*storage.Session{
		{ID: "first-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, ExpiresAt: now.Add(time.Hour)},
		{ID: "second-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, ExpiresAt: now.Add(time.Hour)},
		{ID: "expired-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, ExpiresAt: now.Add(-time.Hour)},
		{ID: "other-session", UserID: other.ID, Username: other.Username, Role: other.Role, CredentialEpoch: other.CredentialEpoch, ExpiresAt: now.Add(time.Hour)},
	} {
		if err := store.CreateSession(ctx, session); err != nil {
			t.Fatal(err)
		}
	}

	output, err := executeUsernameRepairCommand(t, sqlitePath, user.ID, "Recovered.Admin_1", "--reason", "Repair historical whitespace")
	if err != nil {
		t.Fatalf("repair command failed: %v; output=%s", err, output)
	}
	updated, err := store.GetUserByID(ctx, user.ID)
	if err != nil || updated == nil {
		t.Fatalf("get repaired user: user=%+v err=%v", updated, err)
	}
	if updated.Username != "Recovered.Admin_1" || updated.PasswordHash != user.PasswordHash || updated.Role != user.Role || updated.TwoFAEnabled != user.TwoFAEnabled || updated.TwoFASecret != user.TwoFASecret || !updated.CreatedAt.Equal(user.CreatedAt) {
		t.Fatalf("repair changed more than username: before=%+v after=%+v", user, updated)
	}
	old, err := store.GetUserByUsername(ctx, user.Username)
	if err != nil || old != nil {
		t.Fatalf("old username still resolves: user=%+v err=%v", old, err)
	}
	untouched, err := store.GetUserByID(ctx, other.ID)
	if err != nil || untouched == nil || *untouched != *other {
		t.Fatalf("repair changed the canonical account: user=%+v err=%v", untouched, err)
	}
	var unrevoked int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_sessions WHERE user_id=? AND revoked_at=''`, user.ID).Scan(&unrevoked); err != nil || unrevoked != 0 {
		t.Fatalf("repair left sessions unrevoked: count=%d err=%v", unrevoked, err)
	}
	active, err := store.IsSessionActive(ctx, "other-session", other.ID, now)
	if err != nil || !active {
		t.Fatalf("repair revoked another account's session: active=%v err=%v", active, err)
	}

	var auditID, auditUserID, oldName, newName, actor, reason, createdAt string
	var revoked int64
	if err := db.QueryRowContext(ctx, `SELECT id,user_id,old_username,new_username,actor,reason,revoked_sessions,created_at FROM user_username_repairs`).Scan(&auditID, &auditUserID, &oldName, &newName, &actor, &reason, &revoked, &createdAt); err != nil {
		t.Fatalf("read repair audit: %v", err)
	}
	operator, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	if auditID == "" || auditUserID != user.ID || oldName != " admin " || newName != "Recovered.Admin_1" || actor != "os-user:"+operator.Uid || reason != "Repair historical whitespace" || revoked != 3 {
		t.Fatalf("incorrect repair audit: id=%q user=%q old=%q new=%q actor=%q reason=%q revoked=%d", auditID, auditUserID, oldName, newName, actor, reason, revoked)
	}
	if at, err := time.Parse(time.RFC3339Nano, createdAt); err != nil || at.Before(now) || at.After(time.Now().UTC()) {
		t.Fatalf("incorrect repair audit timestamp: %q err=%v", createdAt, err)
	}
	if !strings.Contains(output, auditID) || !strings.Contains(output, fmt.Sprintf("%q", oldName)) || !strings.Contains(output, fmt.Sprintf("%q", newName)) || strings.Contains(output, user.PasswordHash) || strings.Contains(output, user.TwoFASecret) {
		t.Fatalf("repair output lacks safe audit details or contains credentials: %s", output)
	}
	if err := store.DeleteUser(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_username_repairs WHERE id=?`, auditID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("account deletion removed its repair audit: count=%d err=%v", auditCount, err)
	}
}

func TestUserRepairUsernameCommandRejectsUnsafeTargets(t *testing.T) {
	for _, tc := range []struct {
		name, oldName, targetID, newName, reason, wantError string
	}{
		{name: "collision", oldName: " admin ", newName: "admin", reason: "repair", wantError: "already exists"},
		{name: "invalid new name", oldName: " admin ", newName: " fixed ", reason: "repair", wantError: "invalid username"},
		{name: "invisible new name", oldName: " admin ", newName: "fix\u200bed", reason: "repair", wantError: "invalid username"},
		{name: "missing ID", oldName: " admin ", targetID: "missing-id", newName: "fixed", reason: "repair", wantError: "not found"},
		{name: "username is not an ID", oldName: " admin ", targetID: "admin", newName: "fixed", reason: "repair", wantError: "not found"},
		{name: "padded ID", oldName: " admin ", targetID: " padded-id ", newName: "fixed", reason: "repair", wantError: "user ID"},
		{name: "canonical account", oldName: "legacy-admin", newName: "fixed", reason: "repair", wantError: "already canonical"},
		{name: "missing reason", oldName: " admin ", newName: "fixed", wantError: "reason"},
		{name: "blank reason", oldName: " admin ", newName: "fixed", reason: " \t ", wantError: "reason"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, sqlitePath, db, user := historicalUsernameTestUser(t, tc.oldName)
			other := seedPasswordTestUser(t, store, "admin", "other-password-123")
			ctx := context.Background()
			now := time.Now().UTC()
			if err := store.CreateSession(ctx, &storage.Session{ID: "existing-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			targetID := tc.targetID
			if targetID == "" {
				targetID = user.ID
			}
			args := []string{targetID, tc.newName}
			if tc.reason != "" {
				args = append(args, "--reason", tc.reason)
			}
			if output, err := executeUsernameRepairCommand(t, sqlitePath, args...); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("repair error = %v, want %q; output=%s", err, tc.wantError, output)
			}
			for _, original := range []*storage.User{user, other} {
				stored, err := store.GetUserByID(ctx, original.ID)
				if err != nil || stored == nil || *stored != *original {
					t.Fatalf("failed repair changed a user: user=%+v err=%v", stored, err)
				}
			}
			active, err := store.IsSessionActive(ctx, "existing-session", user.ID, now)
			if err != nil || !active {
				t.Fatalf("failed repair revoked a session: active=%v err=%v", active, err)
			}
			var auditCount int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_username_repairs`).Scan(&auditCount); err != nil || auditCount != 0 {
				t.Fatalf("failed repair wrote a success audit: count=%d err=%v", auditCount, err)
			}
		})
	}
}

func TestUserRepairUsernameCommandRollsBackOnPersistenceFailure(t *testing.T) {
	for _, tc := range []struct {
		name, trigger string
	}{
		{name: "session revocation", trigger: `CREATE TRIGGER fail_repair_session BEFORE UPDATE OF revoked_at ON admin_sessions BEGIN SELECT RAISE(ABORT, 'session failure'); END`},
		{name: "audit write", trigger: `CREATE TRIGGER fail_repair_audit BEFORE INSERT ON user_username_repairs BEGIN SELECT RAISE(ABORT, 'audit failure'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, sqlitePath, db, user := historicalUsernameTestUser(t, " admin ")
			ctx := context.Background()
			now := time.Now().UTC()
			if err := store.CreateSession(ctx, &storage.Session{ID: "existing-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, ExpiresAt: now.Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, tc.trigger); err != nil {
				t.Fatal(err)
			}
			if output, err := executeUsernameRepairCommand(t, sqlitePath, user.ID, "fixed", "--reason", "repair"); err == nil || !strings.Contains(err.Error(), "failure") {
				t.Fatalf("repair should fail closed: err=%v output=%s", err, output)
			}
			stored, err := store.GetUserByID(ctx, user.ID)
			if err != nil || stored == nil || *stored != *user {
				t.Fatalf("persistence failure left a partial rename: user=%+v err=%v", stored, err)
			}
			active, err := store.IsSessionActive(ctx, "existing-session", user.ID, now)
			if err != nil || !active {
				t.Fatalf("persistence failure left a partial revocation: active=%v err=%v", active, err)
			}
			var auditCount int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_username_repairs`).Scan(&auditCount); err != nil || auditCount != 0 {
				t.Fatalf("persistence failure left a success audit: count=%d err=%v", auditCount, err)
			}
		})
	}
}

func TestNormalUserCommandsRejectHistoricalInvalidUsernames(t *testing.T) {
	t.Parallel()
	store, sqlitePath, _, user := historicalUsernameTestUser(t, " admin ")
	ctx := context.Background()
	if _, err := renameUser(ctx, sqlitePath, user.Username, "fixed"); !errors.Is(err, identity.ErrInvalidUsername) {
		t.Fatalf("ordinary rename accepted a dirty identity: %v", err)
	}
	if _, err := changeUserPassword(ctx, sqlitePath, user.Username, cliPasswordOptions{Password: "N7v!mKq2PxR"}); !errors.Is(err, identity.ErrInvalidUsername) {
		t.Fatalf("password reset accepted a dirty identity: %v", err)
	}
	if _, err := ensureAdminUser(ctx, sqlitePath, user.Username, cliPasswordOptions{Password: "N7v!mKq2PxR"}); !errors.Is(err, identity.ErrInvalidUsername) {
		t.Fatalf("ensure-admin accepted a dirty identity: %v", err)
	}
	stored, err := store.GetUserByID(ctx, user.ID)
	if err != nil || stored == nil || *stored != *user {
		t.Fatalf("normal command changed the dirty account: user=%+v err=%v", stored, err)
	}
}

func TestRepairUserUsernameRequiresExistingDatabase(t *testing.T) {
	t.Parallel()
	sqlitePath := filepath.Join(t.TempDir(), "missing", "cheesewaf.db")
	if _, err := repairUserUsername(context.Background(), sqlitePath, "user-id", "fixed", "os-user:501", "repair"); err == nil || !strings.Contains(err.Error(), "existing SQLite database") {
		t.Fatalf("repair error = %v, want existing database requirement", err)
	}
	if _, err := os.Stat(filepath.Dir(sqlitePath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed repair created a runtime directory or database: %v", err)
	}
}

func executeUsernameRepairCommand(t *testing.T, sqlitePath string, args ...string) (string, error) {
	t.Helper()
	originalConfigPath, originalDataDir, originalLang := configPath, dataDir, cliLang
	t.Cleanup(func() { configPath, dataDir, cliLang = originalConfigPath, originalDataDir, originalLang })
	root := newRootCommand()
	if command, _, err := root.Find([]string{"user", "repair-username"}); err == nil {
		if flag := command.Flags().Lookup("reason"); flag != nil {
			originalValue, originalChanged := flag.Value.String(), flag.Changed
			_ = flag.Value.Set(flag.DefValue)
			flag.Changed = false
			t.Cleanup(func() { _ = flag.Value.Set(originalValue); flag.Changed = originalChanged })
		}
	}
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.SetArgs(append([]string{"--config", filepath.Join(t.TempDir(), "missing.yaml"), "--data-dir", filepath.Dir(sqlitePath), "user", "repair-username"}, args...))
	err := root.Execute()
	return output.String(), err
}

func historicalUsernameTestUser(t *testing.T, username string) (*storage.SQLiteStore, string, *sql.DB, *storage.User) {
	t.Helper()
	store, sqlitePath := userPasswordTestStore(t)
	user := seedPasswordTestUser(t, store, "legacy-admin", "old-password-123")
	user.TwoFAEnabled = true
	user.TwoFASecret = "legacy-test-secret"
	if err := store.UpdateUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Raw SQL represents data written before canonical username validation existed.
	if _, err := db.Exec(`UPDATE users SET username=? WHERE id=?`, username, user.ID); err != nil {
		t.Fatal(err)
	}
	user.Username = username
	return store, sqlitePath, db, user
}

func userPasswordTestStore(t *testing.T) (*storage.SQLiteStore, string) {
	t.Helper()
	sqlitePath := t.TempDir() + "/cheesewaf.db"
	store, err := storage.OpenSQLite(sqlitePath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return store, sqlitePath
}

func seedPasswordTestUser(t *testing.T, store *storage.SQLiteStore, username, password string) *storage.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user := &storage.User{
		Username:     username,
		PasswordHash: string(hash),
		Role:         "admin",
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}
