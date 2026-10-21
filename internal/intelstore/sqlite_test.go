package intelstore_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
	"github.com/LaokeQwQ/CheeseWAF/internal/intelstore"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func testClock() time.Time {
	return time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)
}

func testExtraction() intel.Extraction {
	return intel.Extraction{
		CVEIDs:     []string{"CVE-2025-1234"},
		Confidence: 0.85,
		Request: intel.RequestShape{
			Method:           "POST",
			Path:             "/uploads/index.php",
			ContentType:      "multipart/form-data",
			UploadProgress:   true,
			SessionParameter: intel.MultipartProgressMarker,
		},
		References: []string{"https://advisory.example.test/CVE-2025-1234"},
	}
}

func testItem() intel.Item {
	sum := sha256.Sum256([]byte("advisory body"))
	return intel.Item{
		ID:          "item-test-0001",
		SourceID:    "src-test",
		Title:       "PHP2Shell advisory",
		ContentHash: hex.EncodeToString(sum[:]),
		PublishedAt: testClock(),
		Products:    []string{"php"},
		References:  []string{"https://advisory.example.test/CVE-2025-1234"},
		RawExcerpt:  "multipart upload progress with PHPSESSID",
	}
}

func testCandidate(t *testing.T) intel.Candidate {
	t.Helper()
	item := testItem()
	rule, err := intel.NewRuleCompiler().Compile(testExtraction(), intel.Scope{SiteID: "site-a"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	candidate, err := intel.NewCandidate(intel.CandidateOptions{
		Item:       item,
		Extraction: testExtraction(),
		Decision:   intel.TrustDecision{Allowed: true, Trust: intel.TrustVendor},
		Rule:       rule,
		TTL:        24 * time.Hour,
		Now:        testClock(),
	})
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	return candidate
}

func newSQLiteIntelStore(t *testing.T) (*storage.SQLiteStore, intelstore.Store) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	intelStore, err := store.IntelStore()
	if err != nil {
		t.Fatalf("intel store: %v", err)
	}
	return store, intelStore
}

func TestSQLiteStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	_, store := newSQLiteIntelStore(t)

	source := intel.Source{
		ID: "src-test", Type: "url", URL: "https://advisory.example.test/feed.xml",
		Trust: intel.TrustVendor, Enabled: true,
	}
	if err := store.UpsertSource(ctx, source); err != nil {
		t.Fatalf("upsert source: %v", err)
	}
	fetched, err := store.GetSource(ctx, source.ID)
	if err != nil {
		t.Fatalf("get source: %v", err)
	}
	if fetched.Trust != intel.TrustVendor || !fetched.Enabled {
		t.Fatalf("source round trip mismatch: %+v", fetched)
	}
	sources, err := store.ListSources(ctx)
	if err != nil || len(sources) != 1 {
		t.Fatalf("list sources: %v %v", sources, err)
	}
	if _, err := store.GetSource(ctx, "missing"); !errors.Is(err, intelstore.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	item := testItem()
	storedItem, created, err := store.InsertItem(ctx, item)
	if err != nil || !created {
		t.Fatalf("insert item: created=%v err=%v", created, err)
	}
	if storedItem.ID != item.ID {
		t.Fatalf("item id mismatch: %q", storedItem.ID)
	}
	duplicate, created, err := store.InsertItem(ctx, item)
	if err != nil || created {
		t.Fatalf("dedupe item: created=%v err=%v", created, err)
	}
	if duplicate.ID != item.ID {
		t.Fatalf("dedupe returned %q", duplicate.ID)
	}
	gotItem, err := store.GetItem(ctx, item.ID)
	if err != nil || gotItem.ContentHash != item.ContentHash || len(gotItem.References) != 1 {
		t.Fatalf("get item: %+v err=%v", gotItem, err)
	}

	candidate := testCandidate(t)
	storedCandidate, created, err := store.InsertCandidate(ctx, candidate)
	if err != nil || !created {
		t.Fatalf("insert candidate: created=%v err=%v", created, err)
	}
	if storedCandidate.Action != intel.ActionLog || storedCandidate.State != intel.CandidateDraft {
		t.Fatalf("candidate must start disabled and log-only: %+v", storedCandidate)
	}
	if _, created, err := store.InsertCandidate(ctx, candidate); err != nil || created {
		t.Fatalf("candidate insert must be idempotent: created=%v err=%v", created, err)
	}

	items, err := store.ListItems(ctx, intelstore.ItemFilter{Limit: 10, State: intel.CandidateDraft})
	if err != nil || len(items) != 1 {
		t.Fatalf("list items by state: %v %v", items, err)
	}
	candidates, err := store.ListCandidates(ctx, intelstore.CandidateFilter{SiteID: "site-a", State: intel.CandidateDraft})
	if err != nil || len(candidates) != 1 {
		t.Fatalf("list candidates: %v %v", candidates, err)
	}

	shadow := intel.CandidateShadow
	updated, err := store.UpdateCandidateState(ctx, candidate.ID, shadow, "alice")
	if err != nil {
		t.Fatalf("update state: %v", err)
	}
	if updated.State != shadow || !updated.Provenance.Approved || updated.Provenance.ApprovedBy != "alice" {
		t.Fatalf("state update mismatch: %+v", updated)
	}

	canary := intel.CandidateCanary
	if _, err := store.UpdateCandidateState(ctx, candidate.ID, canary, "alice"); err != nil {
		t.Fatalf("update canary: %v", err)
	}
	blocked, err := store.UpdateCandidateAction(ctx, candidate.ID, intel.ActionBlock, "alice")
	if err != nil {
		t.Fatalf("update action: %v", err)
	}
	if blocked.Action != intel.ActionBlock {
		t.Fatalf("action not updated: %+v", blocked)
	}
	compiled, err := intel.DecodeCompiledRule([]byte(blocked.RuleJSON))
	if err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	if compiled.Rule.Action != intel.ActionBlock {
		t.Fatalf("rule action not rewritten: %q", compiled.Rule.Action)
	}

	expiry := candidate.CreatedAt.Add(2 * time.Hour)
	expiring, err := store.UpdateCandidateExpiry(ctx, candidate.ID, expiry)
	if err != nil {
		t.Fatalf("update expiry: %v", err)
	}
	if !expiring.ExpiresAt().Equal(expiry) {
		t.Fatalf("expiry mismatch: %s", expiring.ExpiresAt())
	}
	expired, err := store.ExpireCandidates(ctx, candidate.CreatedAt.Add(3*time.Hour))
	if err != nil || expired != 1 {
		t.Fatalf("expire: %d %v", expired, err)
	}
	final, err := store.GetCandidate(ctx, candidate.ID)
	if err != nil || final.State != intel.CandidateExpired {
		t.Fatalf("expired candidate: %+v err=%v", final, err)
	}

	job := intelstore.NewImportJob("job-test-0001", "https://advisory.example.test/a?token=secret#frag", testClock())
	if job.URL != "https://advisory.example.test/a" {
		t.Fatalf("job url must be sanitized: %q", job.URL)
	}
	if err := store.InsertImportJob(ctx, job); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	job.Status = intelstore.ImportStatusCompleted
	job.ContentHash = item.ContentHash
	job.ExtractionJSON = `{"confidence":0.85}`
	job.UpdatedAt = testClock().Add(time.Minute)
	if err := store.UpdateImportJob(ctx, job); err != nil {
		t.Fatalf("update job: %v", err)
	}
	fetchedJob, err := store.GetImportJob(ctx, job.ID)
	if err != nil || fetchedJob.Status != intelstore.ImportStatusCompleted || fetchedJob.ContentHash != item.ContentHash {
		t.Fatalf("get job: %+v err=%v", fetchedJob, err)
	}
	if _, err := store.GetImportJob(ctx, "missing"); !errors.Is(err, intelstore.ErrNotFound) {
		t.Fatalf("expected not found job, got %v", err)
	}
}

func TestSQLiteStoreRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	_, store := newSQLiteIntelStore(t)

	if err := store.UpsertSource(ctx, intel.Source{ID: "bad id", Type: "url", URL: "https://example.test/feed"}); !errors.Is(err, intelstore.ErrInvalid) {
		t.Fatalf("expected invalid source, got %v", err)
	}
	if _, err := store.GetCandidate(ctx, "../etc/passwd"); !errors.Is(err, intelstore.ErrInvalid) {
		t.Fatalf("expected invalid id, got %v", err)
	}
	if _, err := store.ListItems(ctx, intelstore.ItemFilter{State: intel.CandidateState("bogus")}); !errors.Is(err, intelstore.ErrInvalid) {
		t.Fatalf("expected invalid state, got %v", err)
	}
	job := intelstore.NewImportJob("job-test-0002", "https://example.test/a", testClock())
	job.Status = "running"
	if err := store.InsertImportJob(ctx, job); !errors.Is(err, intelstore.ErrInvalid) {
		t.Fatalf("expected invalid job status, got %v", err)
	}
}
