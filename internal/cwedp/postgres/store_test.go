package postgres

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNewRejectsNilDatabase(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil database error=%v", err)
	}
}

func TestValidateStateRejectsCorruptOffsetsDigestsAndTerminalState(t *testing.T) {
	base := testState([]byte("abcdef"), []byte("abc"))
	tests := []struct {
		name string
		edit func(*cwedp.ResumeState)
	}{
		{name: "offset/data mismatch", edit: func(s *cwedp.ResumeState) { s.NextOffset++ }},
		{name: "artifact size mismatch", edit: func(s *cwedp.ResumeState) { s.Intent.Size = 2 }},
		{name: "invalid digest", edit: func(s *cwedp.ResumeState) { s.Intent.Digests.SHA256 = strings.Repeat("A", 64) }},
		{name: "complete before size", edit: func(s *cwedp.ResumeState) { s.Complete = true }},
		{name: "complete and failed", edit: func(s *cwedp.ResumeState) {
			s.NextOffset = s.Intent.Size
			s.Data = []byte("abcdef")
			s.Complete = true
			s.Failed = true
			s.Failure = "failed"
		}},
		{name: "failure text without failure", edit: func(s *cwedp.ResumeState) { s.Failure = "secret=do-not-store" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := base
			state.Data = append([]byte(nil), base.Data...)
			tc.edit(&state)
			if err := validateState(state); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("invalid state accepted: %v", err)
			}
		})
	}
}

func TestValidateTransitionRejectsShortStaleDataWithoutPanic(t *testing.T) {
	current := testState([]byte("abcdef"), []byte("abcd"))
	next := current
	next.NextOffset = 4
	next.Data = []byte("abc")
	if err := validateTransition(current, next); !errors.Is(err, ErrOffsetConflict) {
		t.Fatalf("short stale data error=%v", err)
	}
}

func TestValidateStateRejectsInvalidQuarantineRecords(t *testing.T) {
	base := testState([]byte("abcdef"), []byte("abc"))
	tests := []struct {
		name string
		edit func(*cwedp.ResumeState)
	}{
		{name: "unknown source", edit: func(s *cwedp.ResumeState) {
			s.QuarantinedSources = []cwedp.SourceQuarantine{{Source: cwedp.Source{Kind: cwedp.SourcePeer, ID: "unknown"}, Reason: cwedp.QuarantineTransport}}
		}},
		{name: "unknown reason", edit: func(s *cwedp.ResumeState) {
			s.QuarantinedSources = []cwedp.SourceQuarantine{{Source: s.Source, Reason: cwedp.QuarantineReason("secret")}}
		}},
		{name: "duplicate source", edit: func(s *cwedp.ResumeState) {
			s.QuarantinedSources = []cwedp.SourceQuarantine{{Source: s.Source, Reason: cwedp.QuarantineTransport}, {Source: s.Source, Reason: cwedp.QuarantineIntegrity}}
		}},
		{name: "counter mismatch", edit: func(s *cwedp.ResumeState) {
			s.QuarantinedSources = []cwedp.SourceQuarantine{{Source: s.Source, Reason: cwedp.QuarantineTransport}}
			s.SourceSwitches = 0
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := base
			state.Data = append([]byte(nil), base.Data...)
			tc.edit(&state)
			if !errors.Is(validateState(state), ErrInvalidState) {
				t.Fatalf("invalid quarantine accepted: %v", validateState(state))
			}
		})
	}
}

func TestValidateTransitionRequiresAppendOnlySourceSwitchEvidence(t *testing.T) {
	current := testState([]byte("abcdef"), []byte("abc"))
	next := current
	next.Source = current.Intent.Sources[1]
	next.NextOffset = current.NextOffset
	next.Data = append([]byte(nil), current.Data...)
	next.SourceSwitches = 1
	next.QuarantinedSources = []cwedp.SourceQuarantine{{Source: current.Source, Reason: cwedp.QuarantineTransport}}
	next.UpdatedAt = current.UpdatedAt.Add(time.Second)
	if err := validateTransition(current, next); err != nil {
		t.Fatalf("valid transport source switch rejected: %v", err)
	}
	invalid := next
	invalid.QuarantinedSources = nil
	if !errors.Is(validateTransition(current, invalid), ErrOffsetConflict) {
		t.Fatalf("source switch without quarantine evidence accepted: %v", validateTransition(current, invalid))
	}
	integrity := next
	integrity.Data = nil
	integrity.NextOffset = 0
	integrity.QuarantinedSources = []cwedp.SourceQuarantine{{Source: current.Source, Reason: cwedp.QuarantineIntegrity}}
	integrity.UpdatedAt = current.UpdatedAt.Add(2 * time.Second)
	if err := validateTransition(current, integrity); err != nil {
		t.Fatalf("valid integrity source switch rejected: %v", err)
	}
}

func TestValidateTransitionAllowsOnlyQuarantinedFailedStateRecovery(t *testing.T) {
	failed := testState([]byte("abcdef"), []byte("abc"))
	failed.QuarantinedSources = []cwedp.SourceQuarantine{{Source: failed.Source, Reason: cwedp.QuarantineTransport}}
	failed.SourceSwitches = 1
	failed.Failed = true
	failed.Failure = "no mutually supported distribution source"
	recovered := failed
	recovered.Source = failed.Intent.Sources[1]
	recovered.Failed = false
	recovered.Failure = ""
	recovered.UpdatedAt = failed.UpdatedAt.Add(time.Second)
	if err := validateTransition(failed, recovered); err != nil {
		t.Fatalf("quarantined source recovery rejected: %v", err)
	}
	unsafe := failed
	unsafe.Failed = false
	unsafe.Failure = ""
	unsafe.UpdatedAt = failed.UpdatedAt.Add(time.Second)
	if !errors.Is(validateTransition(failed, unsafe), ErrOffsetConflict) {
		t.Fatalf("failed state cleared without source switch: %v", validateTransition(failed, unsafe))
	}
}

func TestPostgresResumeStoreRoundTripIdempotencyAndFencing(t *testing.T) {
	store, ctx := integrationStore(t)
	full := []byte("cheesewaf-package")
	initial := testState(full, nil)
	if err := store.SaveExpected(ctx, 0, initial); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.SaveExpected(ctx, 0, initial); err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	chunk := testState(full, full[:8])
	if err := store.SaveExpected(ctx, 0, chunk); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := store.SaveExpected(ctx, 0, testState(full, full[:12])); !errors.Is(err, ErrOffsetConflict) {
		t.Fatalf("stale expected offset accepted: %v", err)
	}
	if err := store.SaveExpected(ctx, 8, chunk); err != nil {
		t.Fatalf("idempotent append: %v", err)
	}
	loaded, err := store.Load(ctx, initial.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NextOffset != 8 || string(loaded.Data) != string(full[:8]) || loaded.Intent.Digests != initial.Intent.Digests || loaded.Source != initial.Source {
		t.Fatalf("round trip mismatch: %+v", loaded)
	}
	complete := testState(full, full)
	complete.Complete = true
	if err := store.SaveExpected(ctx, 8, complete); err != nil {
		t.Fatalf("complete: %v", err)
	}
	continued := complete
	continued.Complete = false
	continued.Failed = true
	continued.Failure = "late failure"
	if err := store.SaveExpected(ctx, int64(len(full)), continued); !errors.Is(err, ErrTerminalState) {
		t.Fatalf("terminal state was changed: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
}

func integrationStore(t *testing.T) (*ResumeStore, context.Context) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN"))
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not configured")
	}
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("cwedp_resume_%d", time.Now().UnixNano())
	admin := stdlib.OpenDB(*cfg)
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		_ = admin.Close()
	})
	testCfg := *cfg
	testCfg.RuntimeParams = cloneParams(cfg.RuntimeParams)
	testCfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(testCfg)
	t.Cleanup(func() { _ = db.Close() })
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return store, ctx
}

func cloneParams(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func testState(full, data []byte) cwedp.ResumeState {
	m, a, h := md5.Sum(full), sha1.Sum(full), sha256.Sum256(full)
	return cwedp.ResumeState{
		JobID: "job-1",
		Intent: cwedp.DistributionIntent{
			ID: "job-1", PackageID: "official/demo", Version: "1.0.0", Size: int64(len(full)),
			Digests:   cwedp.Digests{MD5: hex.EncodeToString(m[:]), SHA1: hex.EncodeToString(a[:]), SHA256: hex.EncodeToString(h[:])},
			Sources:   []cwedp.Source{{Kind: cwedp.SourceOffline, ID: "offline"}, {Kind: cwedp.SourcePeer, ID: "peer"}},
			Signature: "signature-reference",
		},
		Source:   cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"},
		MaxChunk: 8, SourceSwitches: 0, MaxSourceSwitches: cwedp.DefaultMaxSourceSwitches, NextOffset: int64(len(data)), Data: append([]byte(nil), data...),
		UpdatedAt: time.Date(2026, 9, 6, 0, 0, int(len(data)), 0, time.UTC),
	}
}
