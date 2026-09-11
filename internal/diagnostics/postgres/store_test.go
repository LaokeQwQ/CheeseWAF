package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/diagnostics"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestMetadataOperationsRejectNonCanonicalIdentifiersBeforeDatabaseUse(t *testing.T) {
	store := &Store{db: &sql.DB{}}
	for _, invalid := range []string{" upload", "upload ", "up\tload", "up\u00a0load", "up\u200bload", "\ufeffupload"} {
		t.Run(invalid, func(t *testing.T) {
			if _, err := store.Get(context.Background(), invalid); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Get(%q) error=%v, want ErrInvalidRecord", invalid, err)
			}
			if err := store.Retry(context.Background(), invalid, "retry"); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Retry(%q) error=%v, want ErrInvalidRecord", invalid, err)
			}
			if err := store.Cancel(context.Background(), invalid, "cancel"); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Cancel(%q) error=%v, want ErrInvalidRecord", invalid, err)
			}
			if _, err := store.Claim(context.Background(), invalid, time.Second); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Claim(%q) error=%v, want ErrInvalidRecord", invalid, err)
			}
		})
	}
}

func TestOutboxOperationsRejectUnsafeIdentifiersAndEmptyStateBeforeDatabaseUse(t *testing.T) {
	base := diagnostics.Outbox{EventID: "event-1", UploadID: "upload-1", Kind: "diagnostic.completed", State: "pending"}
	for _, tc := range []struct {
		name   string
		mutate func(*diagnostics.Outbox)
	}{
		{name: "event whitespace", mutate: func(o *diagnostics.Outbox) { o.EventID = " event-1" }},
		{name: "upload control", mutate: func(o *diagnostics.Outbox) { o.UploadID = "upload\n1" }},
		{name: "kind format", mutate: func(o *diagnostics.Outbox) { o.Kind = "diagnostic\u200b.completed" }},
		{name: "empty state", mutate: func(o *diagnostics.Outbox) { o.State = "" }},
		{name: "unsafe lease owner", mutate: func(o *diagnostics.Outbox) { o.LeaseOwner = "worker\t1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mutate(&o)
			if err := validateOutbox(o); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("validateOutbox error=%v, want ErrInvalidRecord", err)
			}
		})
	}
	for _, invalid := range []struct {
		name, eventID, worker string
	}{
		{name: "event whitespace", eventID: " event-1", worker: "worker-1"},
		{name: "worker empty", eventID: "event-1", worker: ""},
		{name: "worker control", eventID: "event-1", worker: "worker\u200b1"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if err := validateOutboxDelivery(invalid.eventID, invalid.worker); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("validateOutboxDelivery error=%v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestRecordValidationAndMetadataOnly(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatal(err)
	}
	if err := ValidateRecord(diagnostics.Record{UploadID: "u", TenantID: "t", PluginID: "p", PluginVersion: "1", Risk: "high", Target: "target", State: diagnostics.StateQueued, Attempt: 0, MaxAttempts: 3, Bytes: 10, ExpiresAt: time.Now().Add(time.Hour), LeaseID: "l", IdempotencyKey: "i", SHA256Digest: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecord(diagnostics.Record{UploadID: "u", TenantID: "t", PluginID: "p", PluginVersion: "1", Risk: "high", State: diagnostics.StateQueued, SHA256Digest: "secret payload"}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("got %v", err)
	}
}

func TestReasonCodeScrubsUntrustedRetryAndCancelReasons(t *testing.T) {
	longReason := strings.Repeat("x", maxReasonInputLength+1)
	cases := []struct {
		name       string
		reason     string
		retryWant  string
		cancelWant string
	}{
		{name: "ordinary", reason: "temporary backend unavailable", retryWant: "retry.reason.provided", cancelWant: "cancel.reason.provided"},
		{name: "secret", reason: "provider token=super-secret", retryWant: "retry.reason.sensitive", cancelWant: "cancel.reason.sensitive"},
		{name: "dsn", reason: "postgres://admin:password@example.invalid/db", retryWant: "retry.reason.sensitive", cancelWant: "cancel.reason.sensitive"},
		{name: "control", reason: "operator\nrequested", retryWant: "retry.reason.invalid", cancelWant: "cancel.reason.invalid"},
		{name: "unicode format", reason: "operator\u200brequested", retryWant: "retry.reason.invalid", cancelWant: "cancel.reason.invalid"},
		{name: "too long", reason: longReason, retryWant: "retry.reason.truncated", cancelWant: "cancel.reason.truncated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryReasonCode(tc.reason); got != tc.retryWant {
				t.Fatalf("retryReasonCode(%q) = %q, want %q", tc.reason, got, tc.retryWant)
			}
			if got := cancelReasonCode(tc.reason); got != tc.cancelWant {
				t.Fatalf("cancelReasonCode(%q) = %q, want %q", tc.reason, got, tc.cancelWant)
			}
			if len(tc.retryWant) > maxReasonCodeLength || len(tc.cancelWant) > maxReasonCodeLength {
				t.Fatalf("reason code exceeds %d bytes", maxReasonCodeLength)
			}
			if strings.ContainsAny(tc.retryWant+tc.cancelWant, "\x00\r\n\t") {
				t.Fatal("reason code contains control characters")
			}
			if strings.Contains(tc.retryWant+tc.cancelWant, tc.reason) && tc.reason != "" {
				t.Fatal("reason code retained raw reason")
			}
		})
	}
}

type fakeSQLResult struct {
	rows int64
	err  error
}

func (r fakeSQLResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeSQLResult) RowsAffected() (int64, error) { return r.rows, r.err }

func TestRequireOneRowRejectsUnexpectedUpdateCounts(t *testing.T) {
	if err := requireOneRow(fakeSQLResult{rows: 1}); err != nil {
		t.Fatalf("one row: %v", err)
	}
	if err := requireOneRow(fakeSQLResult{rows: 0}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("zero rows error=%v, want ErrStateConflict", err)
	}
	if err := requireOneRow(fakeSQLResult{rows: 2}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("two rows error=%v, want ErrStateConflict", err)
	}
	if err := requireOneRow(fakeSQLResult{err: errors.New("rows unavailable")}); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("rows error=%v, want ErrInvalidStore", err)
	}
}

func TestIntegrationIdempotentClaimRetryCancelAndOutbox(t *testing.T) {
	s, ctx := integrationStore(t)
	now := time.Now().UTC()
	r := diagnostics.Record{UploadID: "u1", TenantID: "tenant-a", PluginID: "plug", PluginVersion: "1", Risk: "high", FairKey: "tenant-a/plug", Target: "target-a", PolicyEpoch: 2, LeaseID: "lease-1", IdempotencyKey: "idem-1", SHA256Digest: strings.Repeat("b", 64), State: diagnostics.StateQueued, MaxAttempts: 3, Bytes: 42, ExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now, Summary: "summary"}
	got, err := s.Put(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Put(ctx, r)
	if err != nil || again.UploadID != got.UploadID {
		t.Fatalf("idem: %v %+v", err, again)
	}
	claimed, err := s.Claim(ctx, "worker-1", time.Minute)
	if err != nil || claimed == nil || claimed.State != diagnostics.StateUploading || claimed.Attempt != 1 {
		t.Fatalf("claim: %v %+v", err, claimed)
	}
	const retryReason = "provider=postgres://admin:password@example.invalid/db token=do-not-store"
	if err := s.Retry(ctx, "u1", retryReason); err != nil {
		t.Fatal(err)
	}
	status, err := s.Get(ctx, "u1")
	if err != nil || status.LastError != "retry.reason.sensitive" || strings.Contains(status.LastError, retryReason) {
		t.Fatalf("retry reason was not classified safely: err=%v last_error=%q", err, status.LastError)
	}
	const cancelReason = "operator\nrequested cancel"
	if err := s.Cancel(ctx, "u1", cancelReason); err != nil {
		t.Fatal(err)
	}
	status, err = s.Get(ctx, "u1")
	if err != nil || status.State != diagnostics.StateCanceled || status.LastError != "cancel.reason.invalid" || strings.Contains(status.LastError, cancelReason) {
		t.Fatalf("cancel: %v %+v", err, status)
	}
	if err := s.AppendOutbox(ctx, diagnostics.Outbox{EventID: "e1", UploadID: "u1", Kind: "diagnostic.completed", State: "pending", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendOutbox(ctx, diagnostics.Outbox{EventID: "e1", UploadID: "u1", Kind: "diagnostic.completed", State: "pending", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.PendingOutbox(ctx, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("outbox: %v %#v", err, rows)
	}
}

func integrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin := stdlib.OpenDB(*cfg)
	schema := "diag_" + strings.ReplaceAll(time.Now().Format("20060102150405.000000000"), ".", "")
	schema = strings.ReplaceAll(schema, "-", "")
	if _, err = admin.ExecContext(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close()
	})
	params := map[string]string{}
	for k, v := range cfg.RuntimeParams {
		params[k] = v
	}
	params["search_path"] = schema
	cfg.RuntimeParams = params
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}
