package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDesiredStateFixtureHasStableDigest(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("testdata", "desired-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Digest(payload); got != "ea0366ef6c2ceb1238da00e15fd86dba0b9cb78217dbbbb919c5f2362c1414c3" {
		t.Fatalf("fixture digest=%s", got)
	}
}

func TestStateMachineLeadershipAndCompareAndSwap(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	m, err := NewStateMachine("cluster-a", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	initial := m.Snapshot()
	if !initial.WriteFrozen || initial.Epoch != 0 || initial.Revision != 0 {
		t.Fatalf("initial state=%+v", initial)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-a", Version: "v1", Payload: []byte(`{"sites":[]}`), Nonce: "n1"}); !errors.Is(err, ErrWritesFrozen) {
		t.Fatalf("proposal before leadership error=%v, want writes frozen", err)
	}
	state, err := m.InstallLeadership(1, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.Epoch != 1 || state.LeaderID != "node-a" || state.WriteFrozen {
		t.Fatalf("leadership state=%+v", state)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 0, Version: "v1", Payload: []byte(`{"sites":[]}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if commit.State.Revision != 1 || commit.Fence.Revision != 1 || commit.Fence.Digest == "" {
		t.Fatalf("commit=%+v", commit)
	}
	m.InstallCommit(commit)
	if err := m.ValidateFence(commit.Fence); err != nil {
		t.Fatalf("fresh fence rejected: %v", err)
	}
	if err := m.ValidateFence(FenceToken{ClusterID: "cluster-a", LeaderID: "node-a", Epoch: 1, Revision: 1, Digest: commit.Fence.Digest, Nonce: "replayed-from-snapshot"}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("unbound last-known-good fence accepted: %v", err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 0, Version: "v2", Payload: []byte(`{"sites":[1]}`), Nonce: "n2"}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale revision error=%v, want stale revision", err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"sites":[1]}`), Nonce: "n1"}); !errors.Is(err, ErrDuplicateNonce) {
		t.Fatalf("duplicate nonce error=%v, want duplicate nonce", err)
	}
}

func TestStateMachineLeadershipChangeInvalidatesFence(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(2, "node-b"); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateFence(commit.Fence); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("old fence error=%v, want stale fence", err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"enabled":false}`), Nonce: "n2"}); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("old leader proposal error=%v, want not leader", err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-b", ExpectedEpoch: 2, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"enabled":false}`), Nonce: "n3"}); err != nil {
		t.Fatalf("new leader proposal failed: %v", err)
	}
}

func TestStateMachineRejectsDifferentLeaderInSameTerm(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-b"); !errors.Is(err, ErrLeadershipConflict) {
		t.Fatalf("same-term leader change error=%v, want leadership conflict", err)
	}
}

func TestStateMachineValidatesDigestAndFreeze(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"mode":"observe"}`)
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: payload, Digest: "deadbeef", Nonce: "n1"}); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("bad digest error=%v, want invalid proposal", err)
	}
	m.FreezeWrites("maintenance window")
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: payload, Nonce: "n2"}); !errors.Is(err, ErrWritesFrozen) {
		t.Fatalf("frozen proposal error=%v, want writes frozen", err)
	}
}

func TestLeadershipChangeRetainsNonceLedger(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"n":1}`), Nonce: "nonce-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(2, "node-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-b", ExpectedEpoch: 2, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"n":2}`), Nonce: "nonce-1"}); !errors.Is(err, ErrDuplicateNonce) {
		t.Fatalf("nonce reused after leadership change: %v", err)
	}
}

func TestUncommittedFenceIsNotAcceptedByDataPlane(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateFence(commit.Fence); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("uncommitted fence accepted: %v", err)
	}
	m.InstallCommit(commit)
	if err := m.ValidateFence(commit.Fence); err != nil {
		t.Fatalf("committed fence rejected: %v", err)
	}
}

func TestInstallCommitRejectsTamperedCommitWithoutMutatingState(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	baseline := m.Snapshot()
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	commit.Fence.LeaderID = "node-b"
	if err := m.InstallCommit(commit); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("tampered InstallCommit error=%v, want ErrInvalidCommit", err)
	}
	if got := m.Snapshot(); got.Revision != baseline.Revision || got.Desired.Digest != baseline.Desired.Digest || got.LeaderID != baseline.LeaderID || got.WriteFrozen != baseline.WriteFrozen {
		t.Fatalf("tampered commit mutated state: %+v", got)
	}
}

func TestInstallCommitRejectsTamperedStateWithValidFenceTuple(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	commit.State.Desired.Version = "v2"
	if err := m.InstallCommit(commit); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("tampered state accepted: %v", err)
	}
}

func TestValidateCommitRequiresExactStateAndFenceRevision(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	commit.State.Revision = 0
	if err := m.ValidateCommit(commit); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("revision mismatch error=%v, want ErrInvalidCommit", err)
	}
}

func TestValidateCurrentCommitRequiresCurrentMaterialization(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	first, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"revision":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(first); err != nil {
		t.Fatal(err)
	}
	second, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"revision":2}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(second); err != nil {
		t.Fatal(err)
	}

	if err := m.ValidateCurrentCommit(second); err != nil {
		t.Fatalf("current commit rejected: %v", err)
	}
	if err := m.ValidateCurrentCommit(first); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("historical current-epoch commit error=%v, want ErrStaleRevision", err)
	}
	if err := m.ValidateCommit(first); err != nil {
		t.Fatalf("ValidateCommit rejected historical current-epoch commit: %v", err)
	}
	if err := m.ValidateFence(first.Fence); err != nil {
		t.Fatalf("ValidateFence rejected historical current-epoch fence: %v", err)
	}
}

func TestValidateCurrentCommitRejectsOldEpochCommit(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	old, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"revision":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(old); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(2, "node-b"); err != nil {
		t.Fatal(err)
	}
	current, err := m.Propose(Proposal{LeaderID: "node-b", ExpectedEpoch: 2, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"revision":2}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(current); err != nil {
		t.Fatal(err)
	}
	if err := m.ValidateCurrentCommit(current); err != nil {
		t.Fatalf("new-leader current commit rejected: %v", err)
	}
	if err := m.ValidateCurrentCommit(old); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("old-epoch commit error=%v, want ErrInvalidCommit", err)
	}
}

func TestValidateCurrentCommitRejectsFenceIdentityMismatches(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Commit)
	}{
		{name: "different digest", mutate: func(commit *Commit) { commit.Fence.Digest = Digest([]byte(`{"different":true}`)) }},
		{name: "different nonce", mutate: func(commit *Commit) { commit.Fence.Nonce = "nonce-other" }},
		{name: "different cluster", mutate: func(commit *Commit) { commit.Fence.ClusterID = "cluster-other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewStateMachine("cluster-a", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.InstallLeadership(1, "node-a"); err != nil {
				t.Fatal(err)
			}
			commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"revision":1}`), Nonce: "nonce-1"})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.InstallCommit(commit); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&commit)
			if err := m.ValidateCurrentCommit(commit); !errors.Is(err, ErrInvalidCommit) {
				t.Fatalf("tampered current commit error=%v, want ErrInvalidCommit", err)
			}
		})
	}
}

func TestValidateCurrentCommitAllowsCurrentCommitUnderLocalFreeze(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"revision":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(commit); err != nil {
		t.Fatal(err)
	}
	m.FreezeWrites("durable store unavailable")
	if err := m.ValidateCurrentCommit(commit); err != nil {
		t.Fatalf("current commit rejected under process-local freeze overlay: %v", err)
	}
}

func TestWithCurrentCommitAllowsCurrentCommitUnderLocalFreeze(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"revision":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(commit); err != nil {
		t.Fatal(err)
	}
	m.FreezeWrites("durable store unavailable")
	called := false
	if err := m.WithCurrentCommit(commit, func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("WithCurrentCommit rejected exact commit under local freeze: %v", err)
	}
	if !called {
		t.Fatal("WithCurrentCommit did not enter callback under local freeze")
	}
}

func TestLoadSnapshotRejectsRegressionAndInvalidNonceLedger(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(2, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	m.InstallCommit(commit)
	regressed := m.Snapshot()
	regressed.Epoch = 0
	if err := m.LoadSnapshot(regressed); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("epoch regression error=%v, want ErrInvalidCommit", err)
	}
	invalidLedger := m.Snapshot()
	invalidLedger.NonceLedger = map[string]Revision{"n1": 0}
	if err := m.LoadSnapshot(invalidLedger); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("invalid nonce ledger error=%v, want ErrInvalidCommit", err)
	}
}

func TestIdentityFieldsRejectWhitespaceInsteadOfTrimming(t *testing.T) {
	if _, err := NewStateMachine(" cluster-a", nil); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("padded cluster id accepted: %v", err)
	}
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, leader := range []string{" node-a", "node-a ", "node-\u200b-a"} {
		if _, err := m.InstallLeadership(1, leader); !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("leader %q accepted: %v", leader, err)
		}
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Proposal{
		{LeaderID: " node-a", Version: "v1", Payload: []byte(`{"x":1}`), Nonce: "n1"},
		{LeaderID: "node-a", Version: " v1", Payload: []byte(`{"x":1}`), Nonce: "n2"},
		{LeaderID: "node-a", Version: "v1", Payload: []byte(`{"x":1}`), Nonce: " n3"},
	} {
		p.ExpectedEpoch = 1
		if _, err := m.Propose(p); !errors.Is(err, ErrInvalidProposal) {
			t.Fatalf("proposal identity accepted: %+v error=%v", p, err)
		}
	}
}

func TestInstallLeadershipRejectsEpochOverflowWithoutMutation(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := m.InstallLeadership(1, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.state.Epoch = ^Epoch(0)
	m.committed.Epoch = ^Epoch(0)
	m.mu.Unlock()
	if _, err := m.InstallLeadership(2, "node-b"); !errors.Is(err, ErrInvalidProposal) {
		t.Fatalf("epoch overflow accepted: %v", err)
	}
	got := m.Snapshot()
	if got.Epoch != ^Epoch(0) || got.LeaderID != state.LeaderID || !got.WriteFrozen {
		t.Fatalf("overflow attempt mutated state: %+v", got)
	}
}

func TestLeadershipCheckpointClearsOnlyNativeRaftAvailabilityFreeze(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.InstallCommit(commit); err != nil {
		t.Fatal(err)
	}
	m.FreezeWrites("native-raft leadership unavailable")
	state, err := m.InstallLeadership(2, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	if state.WriteFrozen {
		t.Fatalf("native-raft leadership checkpoint remained frozen: %+v", state)
	}
	m.FreezeWrites("postgres durable persistence failed")
	state, err = m.InstallLeadership(3, "node-c")
	if err != nil {
		t.Fatal(err)
	}
	if !state.WriteFrozen || state.FreezeReason != "postgres durable persistence failed" {
		t.Fatalf("durable failure freeze was cleared unexpectedly: %+v", state)
	}
}
