package postgres

import (
	"context"
	"database/sql"
	"errors"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"testing"
	"time"
)

func TestConfigurePoolSetsBoundedProductionDefaults(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	configurePool(db)
	if got := db.Stats().MaxOpenConnections; got != defaultMaxOpenConns {
		t.Fatalf("max open connections=%d, want %d", got, defaultMaxOpenConns)
	}
}

type fixtureScanner struct{ values []any }

func (f fixtureScanner) Scan(dest ...any) error {
	if len(dest) != len(f.values) {
		return errors.New("fixture column mismatch")
	}
	for i, value := range f.values {
		switch d := dest[i].(type) {
		case *string:
			*d, _ = value.(string)
		case *bool:
			*d, _ = value.(bool)
		case *int64:
			*d, _ = value.(int64)
		case *dbBool:
			if err := d.Scan(value); err != nil {
				return err
			}
		case *dbTime:
			if err := d.Scan(value); err != nil {
				return err
			}
		default:
			return errors.New("unsupported fixture destination")
		}
	}
	return nil
}

func TestRoleValidationRejectsPermissionExpressionsAndUnknownRoles(t *testing.T) {
	for _, role := range []string{"", " admin ", "admin\t", "admin\u200b", "*", "read:*", "read:logs write:users"} {
		if validateRoleSyntax(role) == nil {
			t.Fatalf("validateRoleSyntax(%q) accepted invalid role", role)
		}
	}
	if !roleAllowed(defaultRoleKeys, "admin") || !roleAllowed(defaultRoleKeys, "readonly") {
		t.Fatal("default management roles are not allowed")
	}
	if roleAllowed(defaultRoleKeys, "operator") {
		t.Fatal("unknown role was accepted by default role set")
	}
}

func TestNewWithRolesAcceptsExactConfiguredRole(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewWithRoles(db, map[string][]string{"operator": {"read:logs"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validatePersistedRole("operator"); err != nil {
		t.Fatalf("configured role rejected: %v", err)
	}
	if err := s.validatePersistedRole("read:*"); err == nil {
		t.Fatal("permission expression accepted as role")
	}
}

func TestCreateAndUpdateUserRejectInvalidOrUnknownRoleBeforeDatabaseUse(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"", "unknown", "read:*", " admin ", "admin\u200b"} {
		user := &storage.User{ID: "u-" + role, Username: "admin", PasswordHash: "hash", Role: role}
		if err := s.CreateUser(context.Background(), user); err == nil {
			t.Fatalf("CreateUser accepted role %q", role)
		}
		if err := s.UpdateUser(context.Background(), user); err == nil {
			t.Fatalf("UpdateUser accepted role %q", role)
		}
	}
}

func TestUserWriteRejectsNonCanonicalIdentifier(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	user := &storage.User{ID: " user-id ", Username: "admin", PasswordHash: "hash", Role: "admin"}
	if err := s.CreateUser(context.Background(), user); err == nil {
		t.Fatal("CreateUser accepted a whitespace user ID")
	}
	if err := s.UpdateUser(context.Background(), user); err == nil {
		t.Fatal("UpdateUser accepted a whitespace user ID")
	}
}

func TestScanUserRejectsDirtyRole(t *testing.T) {
	row := fixtureScanner{values: []any{"id", "admin", "hash", "read:*", false, "", time.Now(), time.Now(), int64(0)}}
	if _, err := scanUser(row); err == nil {
		t.Fatal("scanUser accepted permission expression as persisted role")
	}
}

func TestNewRejectsNilDatabase(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("New(nil) error = %v, want ErrInvalidStore", err)
	}
}

func TestRebindQuestionMarksToPostgresParameters(t *testing.T) {
	got := rebind(`SELECT '?' AS literal, id FROM users WHERE id=? AND username=?`)
	want := `SELECT '?' AS literal, id FROM users WHERE id=$1 AND username=$2`
	if got != want {
		t.Fatalf("rebind() = %q, want %q", got, want)
	}
}

func TestNilStoreOperationsReturnInvalidStore(t *testing.T) {
	var s *Store
	if err := s.Migrate(context.Background()); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil Migrate error = %v, want ErrInvalidStore", err)
	}
}

func TestNilContextOperationsReturnInvalidStore(t *testing.T) {
	db, err := sql.Open("pgx", "postgres://invalid")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil Migrate context error=%v", err)
	}
	if err := s.Health(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil Health context error=%v", err)
	}
}
