package intelstore_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage/postgres"
)

// Opt-in real PostgreSQL test. It is skipped unless the caller provides an
// isolated database DSN through CHEESEWAF_POSTGRES_TEST_DSN.
func TestPostgresStoreRoundTrip(t *testing.T) {
	dsn := os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set CHEESEWAF_POSTGRES_TEST_DSN to run real PostgreSQL tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := db.QueryRowContext(ctx, `SELECT 'cw_intel_' || substr(md5(random()::text),1,12)`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer db.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
	if _, err := db.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	management, err := postgres.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := management.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := management.IntelStore()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.UpsertSource(ctx, intel.Source{
		ID: "src-pg", Type: "url", URL: "https://advisory.example.test/feed.xml",
		Trust: intel.TrustVendor, Enabled: true,
	}); err != nil {
		t.Fatalf("upsert source: %v", err)
	}
	source, err := store.GetSource(ctx, "src-pg")
	if err != nil || !source.Enabled || source.Trust != intel.TrustVendor {
		t.Fatalf("get source: %+v err=%v", source, err)
	}

	item := testItem()
	item.SourceID = "src-pg"
	storedItem, created, err := store.InsertItem(ctx, item)
	if err != nil || !created {
		t.Fatalf("insert item: created=%v err=%v", created, err)
	}
	if _, created, err := store.InsertItem(ctx, item); err != nil || created {
		t.Fatalf("item dedupe: created=%v err=%v", created, err)
	}

	candidate := testCandidate(t)
	candidate.ItemID = storedItem.ID
	candidate.Provenance.ItemID = storedItem.ID
	storedCandidate, created, err := store.InsertCandidate(ctx, candidate)
	if err != nil || !created {
		t.Fatalf("insert candidate: created=%v err=%v", created, err)
	}
	if storedCandidate.State != intel.CandidateDraft || storedCandidate.Action != intel.ActionLog {
		t.Fatalf("candidate=%+v", storedCandidate)
	}
	shadow := intel.CandidateShadow
	if _, err := store.UpdateCandidateState(ctx, candidate.ID, shadow, "alice"); err != nil {
		t.Fatalf("update state: %v", err)
	}
	listed, err := store.ListCandidates(ctx, intelstore.CandidateFilter{SiteID: candidate.SiteID, State: shadow})
	if err != nil || len(listed) != 1 {
		t.Fatalf("list candidates: %v %v", listed, err)
	}

	job := intelstore.NewImportJob("job-pg-0001", "https://advisory.example.test/a", testClock())
	if err := store.InsertImportJob(ctx, job); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	job.Status = intelstore.ImportStatusFailed
	job.Error = "fetch_failed"
	job.UpdatedAt = testClock().Add(time.Minute)
	if err := store.UpdateImportJob(ctx, job); err != nil {
		t.Fatalf("update job: %v", err)
	}
	fetched, err := store.GetImportJob(ctx, job.ID)
	if err != nil || fetched.Status != intelstore.ImportStatusFailed || fetched.Error != "fetch_failed" {
		t.Fatalf("get job: %+v err=%v", fetched, err)
	}
}
