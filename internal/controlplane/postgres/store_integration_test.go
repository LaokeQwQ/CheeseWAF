package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Every test owns a fresh schema, including its cleanup. Never truncate or drop
// pre-existing tables in the database named by the explicit test DSN.
func integrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	dsn := os.Getenv("CHEESEWAF_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("CHEESEWAF_POSTGRES_TEST_DSN is not set")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid PostgreSQL test DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = admin.Close() })
	schema := "cw_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if _, err := admin.ExecContext(cleanupCtx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("clean up own schema: %v", err)
		}
	})
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
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

func integrationCommit(t *testing.T, nonce string) (*controlplane.StateMachine, controlplane.Commit) {
	t.Helper()
	m, err := controlplane.NewStateMachine("integration", func() time.Time {
		return time.Date(2026, 9, 6, 12, 0, 0, 123456789, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.InstallLeadership(1, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Propose(controlplane.Proposal{LeaderID: s.LeaderID, ExpectedEpoch: s.Epoch, Version: "v1", Nonce: nonce,
		Payload: []byte("{ \"z\": 9007199254740993, \"a\": {\"text\": \"<>&\"} }\n")})
	if err != nil {
		t.Fatal(err)
	}
	return m, c
}

func TestIntegrationPreservesPayloadAndChecksAllRetryMetadata(t *testing.T) {
	s, ctx := integrationStore(t)
	_, c := integrationCommit(t, "n1")
	if err := s.AppendCommit(ctx, c); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.LoadState(ctx, c.State.ClusterID)
	if err != nil || string(loaded.Desired.Payload) != string(c.State.Desired.Payload) || loaded.Desired.Digest != c.State.Desired.Digest {
		t.Fatalf("payload round-trip failed: %v", err)
	}
	if err := s.AppendCommit(ctx, c); err != nil {
		t.Fatalf("exact retry rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*controlplane.Commit)
	}{
		{"timestamp", func(c *controlplane.Commit) { c.State.UpdatedAt = c.State.UpdatedAt.Add(time.Second) }},
		{"version", func(c *controlplane.Commit) { c.State.Desired.Version = "v2" }},
		{"term", func(c *controlplane.Commit) { c.State.Term++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := c
			tc.mutate(&changed)
			if err := s.AppendCommit(ctx, changed); !errors.Is(err, ErrCommitConflict) {
				t.Fatalf("changed retry accepted: %v", err)
			}
		})
	}
}

func TestIntegrationPreservesMultiRevisionNonceHistory(t *testing.T) {
	s, ctx := integrationStore(t)
	m, first := integrationCommit(t, "n1")
	second, err := m.Propose(controlplane.Proposal{
		LeaderID: "node-a", ExpectedEpoch: first.State.Epoch, ExpectedRevision: first.State.Revision,
		Version: "v2", Nonce: "n2", Payload: []byte(`{"enabled":true,"revision":2}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommit(ctx, second); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.LoadState(ctx, first.State.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 2 || loaded.NonceLedger["n1"] != 1 || loaded.NonceLedger["n2"] != 2 || string(loaded.Desired.Payload) != string(second.State.Desired.Payload) {
		t.Fatalf("multi-revision state was not preserved: %+v", loaded)
	}
}

func TestIntegrationSerializesCompetingFirstCommits(t *testing.T) {
	s, ctx := integrationStore(t)
	_, a := integrationCommit(t, "a")
	_, b := integrationCommit(t, "b")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, c := range []controlplane.Commit{a, b} {
		go func(c controlplane.Commit) { <-start; results <- s.AppendCommit(ctx, c) }(c)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrCommitConflict) && !errors.Is(err, ErrSequenceGap) {
			t.Errorf("unexpected loser error: %v", err)
		}
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM cheesewaf_controlplane_commits").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if successes != 1 || count != 1 {
		t.Fatalf("competing first commits: successes=%d rows=%d", successes, count)
	}
}

func TestIntegrationRejectsInitialRevisionGap(t *testing.T) {
	s, ctx := integrationStore(t)
	m, first := integrationCommit(t, "n1")
	next, err := m.Propose(controlplane.Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Nonce: "n2", Payload: first.State.Desired.Payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommit(ctx, next); !errors.Is(err, ErrSequenceGap) {
		t.Fatalf("initial revision gap accepted: %v", err)
	}
	if _, err := s.LoadState(ctx, next.State.ClusterID); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("rejected first commit created state: %v", err)
	}
}

func TestIntegrationRollsBackHistoryWhenStateWriteFails(t *testing.T) {
	s, ctx := integrationStore(t)
	_, c := integrationCommit(t, "n1")
	// Force the second write of the transaction to fail without replacing the
	// SQL driver. Both tables belong exclusively to this test's schema.
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE cheesewaf_controlplane_state ADD CONSTRAINT reject_test_state CHECK (revision = 0)"); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommit(ctx, c); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("forced state-write failure: %v", err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM cheesewaf_controlplane_commits").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed state write left a committed history row")
	}
}

func TestIntegrationRollsBackLaterRevisionWhenStateWriteFails(t *testing.T) {
	s, ctx := integrationStore(t)
	m, first := integrationCommit(t, "n1")
	second, err := m.Propose(controlplane.Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Nonce: "n2", Payload: []byte(`{"revision":2}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommit(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE cheesewaf_controlplane_state ADD CONSTRAINT reject_later_revision CHECK (revision <= 1)"); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCommit(ctx, second); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("forced later state-write failure: %v", err)
	}
	loaded, err := s.LoadState(ctx, first.State.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 1 || len(loaded.NonceLedger) != 1 {
		t.Fatalf("later failure changed existing state: %+v", loaded)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM cheesewaf_controlplane_commits").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("later failure left %d history rows", count)
	}
}

// The consensus double records ordering only. This test proves the real PG
// adapter works through Coordinator; it does not test native-raft replication.
type integrationConsensus struct{ state controlplane.State }

func (c *integrationConsensus) Current(context.Context, string) (controlplane.State, error) {
	return c.state, nil
}
func (c *integrationConsensus) Propose(_ context.Context, commit controlplane.Commit) error {
	c.state = commit.State
	return nil
}

func TestIntegrationCoordinatorFirstCommitAndRestore(t *testing.T) {
	s, ctx := integrationStore(t)
	m, c := integrationCommit(t, "n1")
	consensus := &integrationConsensus{}
	coordinator, err := controlplane.NewCoordinator(m, consensus, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateFence(c.Fence); err != nil {
		t.Fatal(err)
	}
	restored, err := controlplane.NewStateMachine(c.State.ClusterID, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := controlplane.NewCoordinator(restored, consensus, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.LoadSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if restored.Snapshot().Revision != 1 {
		t.Fatal("committed revision not restored")
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
}

func TestIntegrationLeadershipCheckpointPreservesDesiredCommitHistory(t *testing.T) {
	store, ctx := integrationStore(t)
	_, commit := integrationCommit(t, "checkpoint-nonce")
	if err := store.AppendCommit(ctx, commit); err != nil {
		t.Fatal(err)
	}
	next := commit.State
	next.LeaderID = "node-b"
	next.Term = commit.State.Term + 1
	next.Epoch = commit.State.Epoch + 1
	next.UpdatedAt = commit.State.UpdatedAt.Add(time.Second)
	if err := store.CheckpointLeadership(ctx, next); err != nil {
		t.Fatalf("checkpoint leadership: %v", err)
	}
	loaded, err := store.LoadState(ctx, next.ClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LeaderID != next.LeaderID || loaded.Term != next.Term || loaded.Epoch != next.Epoch || loaded.Revision != commit.State.Revision || loaded.Desired.Digest != commit.State.Desired.Digest || string(loaded.Desired.Payload) != string(commit.State.Desired.Payload) || loaded.NonceLedger[commit.Fence.Nonce] != commit.State.Revision {
		t.Fatalf("checkpoint changed desired state or lost leadership: %+v", loaded)
	}
	var historyLeader string
	var historyTerm int64
	if err := store.db.QueryRowContext(ctx, `SELECT leader_id,term FROM cheesewaf_controlplane_commits WHERE cluster_id=$1 AND revision=$2`, next.ClusterID, int64(next.Revision)).Scan(&historyLeader, &historyTerm); err != nil {
		t.Fatal(err)
	}
	if historyLeader != commit.State.LeaderID || historyTerm != int64(commit.State.Term) {
		t.Fatalf("checkpoint rewrote immutable commit history: leader=%q term=%d", historyLeader, historyTerm)
	}
}
