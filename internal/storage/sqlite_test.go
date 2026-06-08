package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreSiteLifecycle(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	site := &Site{Name: "example", Domains: []string{"example.test"}, Upstreams: []string{"127.0.0.1:9000"}, Enabled: true}
	if err := store.CreateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	sites, err := store.ListSites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Domains[0] != "example.test" {
		t.Fatalf("unexpected sites: %+v", sites)
	}
}

func TestSQLiteStoreSessionLifecycle(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user := &User{ID: "user-1", Username: "admin", PasswordHash: "hash", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	first := &Session{ID: "session-1", UserID: user.ID, Username: user.Username, Role: user.Role, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateSession(ctx, first); err != nil {
		t.Fatal(err)
	}
	active, err := store.IsSessionActive(ctx, first.ID, user.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("expected new session to be active")
	}
	next := &Session{ID: "session-2", UserID: user.ID, Username: user.Username, Role: user.Role, IssuedAt: now.Add(time.Minute), ExpiresAt: now.Add(2 * time.Hour)}
	if err := store.RotateSession(ctx, first.ID, user.ID, next); err != nil {
		t.Fatal(err)
	}
	oldActive, err := store.IsSessionActive(ctx, first.ID, user.ID, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if oldActive {
		t.Fatal("expected rotated session to be revoked")
	}
	nextActive, err := store.IsSessionActive(ctx, next.ID, user.ID, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !nextActive {
		t.Fatal("expected replacement session to be active")
	}
	if err := store.RevokeSession(ctx, next.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	revokedActive, err := store.IsSessionActive(ctx, next.ID, user.ID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revokedActive {
		t.Fatal("expected revoked session to be inactive")
	}
	expired := &Session{ID: "session-expired", UserID: user.ID, Username: user.Username, Role: user.Role, IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := store.CreateSession(ctx, expired); err != nil {
		t.Fatal(err)
	}
	expiredActive, err := store.IsSessionActive(ctx, expired.ID, user.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if expiredActive {
		t.Fatal("expected expired session to be inactive")
	}
	activeOne := &Session{ID: "session-active-one", UserID: user.ID, Username: user.Username, Role: user.Role, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	activeTwo := &Session{ID: "session-active-two", UserID: user.ID, Username: user.Username, Role: user.Role, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.CreateSession(ctx, activeOne); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, activeTwo); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeUserSessions(ctx, user.ID, activeTwo.ID); err != nil {
		t.Fatal(err)
	}
	activeOneStillActive, err := store.IsSessionActive(ctx, activeOne.ID, user.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if activeOneStillActive {
		t.Fatal("expected user-wide revocation to revoke non-excepted session")
	}
	activeTwoStillActive, err := store.IsSessionActive(ctx, activeTwo.ID, user.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !activeTwoStillActive {
		t.Fatal("expected excepted session to remain active")
	}
	pruned, err := store.PruneSessions(ctx, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if pruned == 0 {
		t.Fatal("expected prune to delete expired or old revoked sessions")
	}
}
