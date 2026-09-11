package storage

import (
	"context"
	"testing"
	"time"
)

func TestSQLiteUpdateUserRejectsStaleCredentials(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	user := &User{ID: "epoch-user", Username: "epoch-user", PasswordHash: "old", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	stale := *user
	current := *user
	current.PasswordHash = "new"
	if err := store.UpdateUser(ctx, &current); err != nil {
		t.Fatal(err)
	}
	stale.PasswordHash = "stale-write"
	if err := store.UpdateUser(ctx, &stale); err == nil {
		t.Fatal("stale credential update must be rejected")
	}
	got, err := store.GetUserByID(ctx, user.ID)
	if err != nil || got == nil || got.PasswordHash != "new" {
		t.Fatalf("stale update changed user: got=%+v err=%v", got, err)
	}
}

func TestSQLiteUpdateUserRejectsMissingUser(t *testing.T) {
	store := identityTestStore(t)
	missing := &User{ID: "missing-user", Username: "missing-user", PasswordHash: "hash", Role: "admin"}
	if err := store.UpdateUser(context.Background(), missing); err == nil {
		t.Fatal("updating a missing user must return an error")
	}
}

func TestSQLiteCreateSessionRejectsCredentialsFromBeforeUpdate(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	user := &User{ID: "session-user", Username: "session-user", PasswordHash: "old", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pending := &Session{ID: "pending-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	updated := *user
	updated.PasswordHash = "new"
	if err := store.UpdateUser(ctx, &updated); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, pending); err == nil {
		t.Fatal("session authenticated before the password update must be rejected")
	}
	active, err := store.IsSessionActive(ctx, pending.ID, user.ID, now)
	if err != nil || active {
		t.Fatalf("stale session active=%v err=%v", active, err)
	}
}

func TestSQLiteRevokeUserSessionsRejectsAlreadyPendingSession(t *testing.T) {
	store := identityTestStore(t)
	ctx := context.Background()
	user := &User{ID: "revoke-user", Username: "revoke-user", PasswordHash: "hash", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	pending := &Session{ID: "pending-session", UserID: user.ID, Username: user.Username, Role: user.Role, CredentialEpoch: user.CredentialEpoch, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.RevokeUserSessions(ctx, user.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, pending); err == nil {
		t.Fatal("user-wide revocation must reject an already pending session")
	}
	active, err := store.IsSessionActive(ctx, pending.ID, user.ID, now)
	if err != nil || active {
		t.Fatalf("stale session active=%v err=%v", active, err)
	}
}
