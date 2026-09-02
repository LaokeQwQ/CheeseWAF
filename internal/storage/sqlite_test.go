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

func TestSQLiteConnectionPragmasAndSessionLifecycle(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	var busyTimeout, foreignKeys int
	if err := store.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if busyTimeout != 5000 || foreignKeys != 1 {
		t.Fatalf("unexpected SQLite pragmas: busy_timeout=%d foreign_keys=%d", busyTimeout, foreignKeys)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	user := &User{ID: "pragma-user", Username: "pragma-admin", PasswordHash: "hash", Role: "admin"}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	session := &Session{ID: "pragma-session", UserID: user.ID, Username: user.Username, Role: user.Role, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	active, err := store.IsSessionActive(ctx, session.ID, user.ID, time.Now().UTC())
	if err != nil || !active {
		t.Fatalf("session behavior regressed: active=%v err=%v", active, err)
	}
}

func TestDeleteSiteRemovesAllDirectSQLiteSiteData(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "cheesewaf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	site := &Site{ID: "delete-site", Name: "example", Domains: []string{"example.test"}, Upstreams: []string{"127.0.0.1:9000"}, Enabled: true}
	if err := store.CreateSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRule(ctx, &Rule{ID: "delete-rule", SiteID: site.ID, Name: "rule", Pattern: "blocked"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateReviewItem(ctx, &ReviewItem{ID: "delete-review", SiteID: site.ID, Status: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertSitePromote(ctx, site.ID, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSite(ctx, site.ID); err != nil {
		t.Fatal(err)
	}
	rules, err := store.ListRules(ctx, site.ID)
	if err != nil {
		t.Fatal(err)
	}
	items, total, err := store.ListReviewItems(ctx, ReviewFilter{SiteID: site.ID})
	if err != nil {
		t.Fatal(err)
	}
	promotes, err := store.ListSitePromotes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 || total != 0 || len(items) != 0 || len(promotes) != 0 {
		t.Fatalf("site-linked data remained: rules=%+v reviews=%+v total=%d promotes=%+v", rules, items, total, promotes)
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
