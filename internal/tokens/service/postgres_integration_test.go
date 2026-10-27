package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/tokens"
	tokenspostgres "github.com/LaokeQwQ/CheeseWAF/internal/tokens/postgres"
)

func postgresTestDSN(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	return dsn
}

func newPostgresService(t *testing.T, dsn, tenant string) (*Service, *testClock) {
	t.Helper()
	ctx := context.Background()
	store, err := tokenspostgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	clock := &testClock{now: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	service, err := New(Config{
		Persistence: store,
		Clock:       clock,
		Epochs:      &epochMap{epochs: map[string]uint64{tenant: 5}},
		LeaseID:     "lease-pg-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, clock
}

// A token issued by one process must authenticate in a second process that only
// shares the PostgreSQL database, and a revoke must be durable across restarts.
func TestDurableTokenSurvivesProcessRestart(t *testing.T) {
	dsn := postgresTestDSN(t)
	tenant := fmt.Sprintf("service-restart-%d", time.Now().UnixNano())
	first, _ := newPostgresService(t, dsn, tenant)
	issued, err := first.Issue(context.Background(), IssueRequest{
		TenantID:       tenant,
		IdempotencyKey: "restart-issue-1",
		Request: tokens.CreateRequest{
			Owner:       "operator",
			Name:        "deploy-bot",
			Permissions: []string{"write"},
			Resources:   []string{"sites"},
			PolicyEpoch: 5,
			TTL:         time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	second, _ := newPostgresService(t, dsn, tenant)
	meta, err := second.Authenticate(context.Background(), AuthenticateRequest{
		TenantID:       tenant,
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		PolicyEpoch:    5,
		IdempotencyKey: "restart-auth-1",
	})
	if err != nil {
		t.Fatalf("token did not survive restart: %v", err)
	}
	if meta.Name != "deploy-bot" || meta.Owner != "operator" {
		t.Fatalf("metadata lost display fields: %+v", meta)
	}
	if len(meta.Permissions) != 1 || meta.Permissions[0] != "write" || len(meta.Resources) != 1 || meta.Resources[0] != "sites" {
		t.Fatalf("metadata lost scope: %+v", meta)
	}

	if err := second.Revoke(context.Background(), RevokeRequest{
		TenantID:       tenant,
		TokenID:        issued.Metadata.ID,
		Actor:          "operator",
		PolicyEpoch:    5,
		IdempotencyKey: "restart-revoke-1",
	}); err != nil {
		t.Fatal(err)
	}
	third, _ := newPostgresService(t, dsn, tenant)
	if _, err := third.Authenticate(context.Background(), AuthenticateRequest{
		TenantID:       tenant,
		TokenID:        issued.Metadata.ID,
		Secret:         issued.Secret,
		PolicyEpoch:    5,
		IdempotencyKey: "restart-auth-2",
	}); err == nil {
		t.Fatal("revoked token authenticated after restart")
	}
}

func TestDurableTokenListAndCleanupOnPostgres(t *testing.T) {
	dsn := postgresTestDSN(t)
	tenant := fmt.Sprintf("service-cleanup-%d", time.Now().UnixNano())
	service, clock := newPostgresService(t, dsn, tenant)
	if _, err := service.Issue(context.Background(), IssueRequest{
		TenantID:       tenant,
		IdempotencyKey: "cleanup-issue-1",
		Request: tokens.CreateRequest{
			Owner:       "operator",
			Name:        "short-lived",
			Permissions: []string{"read"},
			Resources:   []string{"logs"},
			PolicyEpoch: 5,
			TTL:         30 * time.Minute,
		},
	}); err != nil {
		t.Fatal(err)
	}
	items, err := service.List(context.Background(), tenant)
	if err != nil || len(items) != 1 || items[0].Name != "short-lived" {
		t.Fatalf("items=%+v err=%v", items, err)
	}
	clock.Set(clock.Now().Add(2 * time.Hour))
	removed, err := service.Cleanup(context.Background(), tenant)
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	items, err = service.List(context.Background(), tenant)
	if err != nil || len(items) != 0 {
		t.Fatalf("items after cleanup=%+v err=%v", items, err)
	}
}
