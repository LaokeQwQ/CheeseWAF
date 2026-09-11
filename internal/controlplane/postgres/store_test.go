package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

func TestNewRejectsNilDatabase(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil database error=%v", err)
	}
}

func TestValidateCommitRejectsPostgresIntegerOverflow(t *testing.T) {
	commit := controlplane.Commit{
		State: controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: controlplane.Epoch(^uint64(0)), Revision: 1, Desired: controlplane.DesiredState{Version: "v", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}},
		Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "l", Epoch: controlplane.Epoch(^uint64(0)), Revision: 1, Digest: controlplane.Digest([]byte("x")), Nonce: "n"},
	}
	if err := validateCommitFields(commit); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("overflowing epoch accepted: %v", err)
	}
}

func TestSameStateIncludesNonceLedger(t *testing.T) {
	a := controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: 1, Revision: 1, Desired: controlplane.DesiredState{Version: "v", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n1": 1}}
	b := a
	b.NonceLedger = map[string]controlplane.Revision{"n2": 1}
	if sameState(a, b) {
		t.Fatal("nonce ledger mismatch treated as idempotent")
	}
}

func TestSameStateIncludesUpdatedAt(t *testing.T) {
	timeA := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	timeB := timeA.Add(time.Second)
	a := controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: 1, Revision: 1, UpdatedAt: timeA, Desired: controlplane.DesiredState{Version: "v", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n1": 1}}
	b := a
	b.UpdatedAt = timeB
	if sameState(a, b) {
		t.Fatal("updated_at mismatch treated as idempotent")
	}
}

func TestValidateCommitRequiresCurrentNonceLedgerEntry(t *testing.T) {
	commit := controlplane.Commit{
		State: controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: 1, Revision: 1, Desired: controlplane.DesiredState{Version: "v", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}},
		Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "l", Epoch: 1, Revision: 1, Digest: controlplane.Digest([]byte("x")), Nonce: "n"},
	}
	if err := validateCommitFields(commit); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("commit without nonce ledger accepted: %v", err)
	}
}

func TestValidateCommitRejectsZeroUpdatedAt(t *testing.T) {
	commit := controlplane.Commit{
		State: controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: 1, Revision: 1, Desired: controlplane.DesiredState{Version: "v", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n": 1}},
		Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "l", Epoch: 1, Revision: 1, Digest: controlplane.Digest([]byte("x")), Nonce: "n"},
	}
	if err := validateCommitFields(commit); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("zero updated_at accepted: %v", err)
	}
}

func TestValidateCommitRejectsNonceLedgerWithMissingHistory(t *testing.T) {
	commit := controlplane.Commit{
		State: controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: 1, Revision: 2, UpdatedAt: time.Now(), Desired: controlplane.DesiredState{Version: "v", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n2": 2}},
		Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "l", Epoch: 1, Revision: 2, Digest: controlplane.Digest([]byte("x")), Nonce: "n2"},
	}
	if err := validateCommitFields(commit); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("incomplete nonce history accepted: %v", err)
	}
}

func TestValidateCommitRejectsInvalidDesiredJSON(t *testing.T) {
	commit := controlplane.Commit{
		State: controlplane.State{ClusterID: "c", LeaderID: "l", Term: 1, Epoch: 1, Revision: 1, UpdatedAt: time.Now(), Desired: controlplane.DesiredState{Version: "v", Payload: []byte("not-json"), Digest: controlplane.Digest([]byte("not-json"))}, NonceLedger: map[string]controlplane.Revision{"n": 1}},
		Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "l", Epoch: 1, Revision: 1, Digest: controlplane.Digest([]byte("not-json")), Nonce: "n"},
	}
	if err := validateCommitFields(commit); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("invalid desired JSON accepted: %v", err)
	}
}

func TestValidateCommitRejectsWhitespaceAndInvisibleIdentityFields(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	base := controlplane.Commit{
		State: controlplane.State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, Revision: 1, UpdatedAt: time.Now().UTC(), Desired: controlplane.DesiredState{Version: "v1", Payload: payload, Digest: controlplane.Digest(payload)}, NonceLedger: map[string]controlplane.Revision{"nonce-1": 1}},
		Fence: controlplane.FenceToken{ClusterID: "cluster-a", LeaderID: "node-a", Epoch: 1, Revision: 1, Digest: controlplane.Digest(payload), Nonce: "nonce-1"},
	}
	for _, mutate := range []func(*controlplane.Commit){
		func(c *controlplane.Commit) { c.State.ClusterID = " cluster-a"; c.Fence.ClusterID = " cluster-a" },
		func(c *controlplane.Commit) { c.State.LeaderID = "node-a "; c.Fence.LeaderID = "node-a " },
		func(c *controlplane.Commit) { c.State.Desired.Version = "v1\u200b" },
		func(c *controlplane.Commit) { c.Fence.Nonce = " nonce-1" },
	} {
		mutated := base
		mutated.State.NonceLedger = map[string]controlplane.Revision{"nonce-1": 1}
		mutate(&mutated)
		if err := validateCommitFields(mutated); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("invalid identity accepted: %+v error=%v", mutated, err)
		}
	}
}

func TestDecodeStateRejectsWhitespaceAndInvisibleIdentityFields(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	digest := controlplane.Digest(payload)
	ledger := []byte(`{"nonce-1":1}`)
	for _, tc := range []struct {
		name, cluster, leader, version string
	}{
		{"cluster", " cluster-a", "node-a", "v1"},
		{"leader", "cluster-a", "node-a ", "v1"},
		{"version", "cluster-a", "node-a", "v1\u200b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeState(tc.cluster, tc.leader, 1, 1, 1, tc.version, digest, payload, false, "", time.Now().UTC(), ledger); !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("invalid identity accepted: %v", err)
			}
		})
	}
}

func TestValidateTransitionRequiresNewNonceToBeFenceNonce(t *testing.T) {
	current := controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 1, Epoch: 1, Revision: 1, NonceLedger: map[string]controlplane.Revision{"n1": 1}}
	commit := controlplane.Commit{State: controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 1, Epoch: 1, Revision: 2, Desired: controlplane.DesiredState{Version: "v2", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n1": 1, "other": 2}}, Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "leader-a", Epoch: 1, Revision: 2, Digest: controlplane.Digest([]byte("x")), Nonce: "n2"}}
	if err := validateTransition(current, commit); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("nonce mismatch error=%v", err)
	}
}

func TestValidateTransitionRejectsFrozenBaseline(t *testing.T) {
	current := controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 1, Epoch: 1, Revision: 0, WriteFrozen: true}
	commit := controlplane.Commit{State: controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 1, Epoch: 1, Revision: 1, Desired: controlplane.DesiredState{Version: "v1", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n1": 1}}, Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "leader-a", Epoch: 1, Revision: 1, Digest: controlplane.Digest([]byte("x")), Nonce: "n1"}}
	if err := validateTransition(current, commit); !errors.Is(err, ErrWritesFrozen) {
		t.Fatalf("frozen baseline error=%v", err)
	}
}

func TestValidateTransitionRejectsTermAndLeaderRegression(t *testing.T) {
	current := controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 5, Epoch: 1, Revision: 1, NonceLedger: map[string]controlplane.Revision{"n1": 1}}
	base := controlplane.Commit{State: controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 4, Epoch: 1, Revision: 2, Desired: controlplane.DesiredState{Version: "v2", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n1": 1, "n2": 2}}, Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "leader-a", Epoch: 1, Revision: 2, Digest: controlplane.Digest([]byte("x")), Nonce: "n2"}}
	if err := validateTransition(current, base); !errors.Is(err, ErrStaleCommit) {
		t.Fatalf("term regression error=%v", err)
	}
	base.State.Term = 5
	base.State.LeaderID, base.Fence.LeaderID = "leader-b", "leader-b"
	if err := validateTransition(current, base); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("leader change in same epoch error=%v", err)
	}
}

func TestValidateTransitionAllowsEpochJumpWithHigherTerm(t *testing.T) {
	current := controlplane.State{ClusterID: "c", LeaderID: "leader-a", Term: 5, Epoch: 1, Revision: 1, NonceLedger: map[string]controlplane.Revision{"n1": 1}}
	commit := controlplane.Commit{State: controlplane.State{ClusterID: "c", LeaderID: "leader-b", Term: 9, Epoch: 3, Revision: 2, Desired: controlplane.DesiredState{Version: "v2", Payload: []byte("x"), Digest: controlplane.Digest([]byte("x"))}, NonceLedger: map[string]controlplane.Revision{"n1": 1, "n2": 2}}, Fence: controlplane.FenceToken{ClusterID: "c", LeaderID: "leader-b", Epoch: 3, Revision: 2, Digest: controlplane.Digest([]byte("x")), Nonce: "n2"}}
	if err := validateTransition(current, commit); err != nil {
		t.Fatalf("valid epoch jump rejected: %v", err)
	}
}

func TestValidateLeadershipCheckpointTransitionOnlyChangesLeadershipMetadata(t *testing.T) {
	payload := []byte(`{"mode":"observe"}`)
	current := controlplane.State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, Revision: 1, Desired: controlplane.DesiredState{Version: "v1", Payload: payload, Digest: controlplane.Digest(payload)}, NonceLedger: map[string]controlplane.Revision{"nonce-1": 1}, UpdatedAt: time.Now().UTC()}
	next := current
	next.LeaderID, next.Term, next.Epoch = "node-b", 2, 2
	next.UpdatedAt = next.UpdatedAt.Add(time.Second)
	if err := validateLeadershipCheckpointTransition(current, next); err != nil {
		t.Fatalf("valid leadership checkpoint rejected: %v", err)
	}
	changedPayload := next
	changedPayload.Desired.Payload = []byte(`{"mode":"enforce"}`)
	changedPayload.Desired.Digest = controlplane.Digest(changedPayload.Desired.Payload)
	if err := validateLeadershipCheckpointTransition(current, changedPayload); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("payload-changing checkpoint error=%v", err)
	}
	regressed := next
	regressed.Term = current.Term
	if err := validateLeadershipCheckpointTransition(current, regressed); !errors.Is(err, ErrStaleCommit) {
		t.Fatalf("term-regressing checkpoint error=%v", err)
	}
}

func TestDecodeStateRejectsCorruptCommittedPayloadOrNonceLedger(t *testing.T) {
	validPayload := []byte(`{"ok":true}`)
	validDigest := controlplane.Digest(validPayload)
	for _, tc := range []struct {
		name, digest    string
		payload, ledger []byte
	}{
		{name: "digest mismatch", digest: strings.Repeat("0", 64), payload: validPayload, ledger: []byte(`{"n":1}`)},
		{name: "missing ledger", digest: validDigest, payload: validPayload, ledger: nil},
		{name: "bad ledger", digest: validDigest, payload: validPayload, ledger: []byte("not-json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeState("c", "l", 1, 1, 1, "v1", tc.digest, tc.payload, false, "", time.Now(), tc.ledger); !errors.Is(err, ErrInvalidStore) {
				t.Fatalf("corrupt state accepted: %v", err)
			}
		})
	}
}

func TestDecodeStateRejectsIncompleteNonceLedger(t *testing.T) {
	payload := []byte(`{"ok":true}`)
	for _, ledger := range []string{`{"n1":1}`, `{"n2":2}`, `{"n1":2,"n2":2}`} {
		if _, err := decodeState("c", "l", 1, 1, 2, "v1", controlplane.Digest(payload), payload, false, "", time.Now(), []byte(ledger)); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("incomplete or duplicate nonce history %s accepted: %v", ledger, err)
		}
	}
}

func TestIntegrationAppendCommitIsIdempotentAndRejectsConflicts(t *testing.T) {
	store, ctx := integrationStore(t)
	m, err := controlplane.NewStateMachine("pg-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := m.InstallLeadership(1, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(controlplane.Proposal{LeaderID: "node-a", ExpectedEpoch: state.Epoch, Version: "v1", Payload: []byte(`{"enabled":true}`), Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendCommit(ctx, commit); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendCommit(ctx, commit); err != nil {
		t.Fatalf("idempotent append failed: %v", err)
	}
	conflict := commit
	conflict.State.Desired.Payload = []byte(`{"enabled":false}`)
	conflict.State.Desired.Digest = controlplane.Digest(conflict.State.Desired.Payload)
	conflict.Fence.Digest = conflict.State.Desired.Digest
	if err := store.AppendCommit(ctx, conflict); !errors.Is(err, ErrCommitConflict) {
		t.Fatalf("conflicting append error=%v", err)
	}
	loaded, err := store.LoadState(ctx, "pg-test")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Revision != 1 || loaded.Desired.Digest != commit.State.Desired.Digest {
		t.Fatalf("loaded=%+v", loaded)
	}
}
