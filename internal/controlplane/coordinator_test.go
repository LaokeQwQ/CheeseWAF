package controlplane

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeConsensus struct {
	log       *[]string
	current   State
	proposals []Commit
	err       error
}

type blockingConsensus struct {
	current State
	started chan struct{}
	release chan struct{}
}

func (b *blockingConsensus) Current(context.Context, string) (State, error) {
	return b.current, nil
}

func (b *blockingConsensus) Propose(_ context.Context, commit Commit) error {
	close(b.started)
	<-b.release
	b.current = commit.State
	return nil
}

func (f *fakeConsensus) Current(context.Context, string) (State, error) {
	if f.err != nil {
		return State{}, f.err
	}
	return f.current, nil
}

func (f *fakeConsensus) Propose(_ context.Context, c Commit) error {
	*f.log = append(*f.log, "consensus")
	if f.err != nil {
		return f.err
	}
	f.proposals = append(f.proposals, c)
	f.current = c.State
	return nil
}

type fakeDurable struct {
	log     *[]string
	state   State
	commits []Commit
	err     error
	loadErr error
}

func (f *fakeDurable) LoadState(context.Context, string) (State, error) {
	if f.loadErr != nil {
		return State{}, f.loadErr
	}
	return f.state, nil
}

func (f *fakeDurable) AppendCommit(_ context.Context, c Commit) error {
	*f.log = append(*f.log, "durable")
	if f.err != nil {
		return f.err
	}
	f.commits = append(f.commits, c)
	f.state = c.State
	return nil
}

func newCoordinatorFixture(t *testing.T) (*StateMachine, *Coordinator, *fakeConsensus, *fakeDurable) {
	t.Helper()
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	log := make([]string, 0, 4)
	c := &fakeConsensus{log: &log, current: m.Snapshot()}
	d := &fakeDurable{log: &log, state: m.Snapshot()}
	coordinator, err := NewCoordinator(m, c, d)
	if err != nil {
		t.Fatal(err)
	}
	return m, coordinator, c, d
}

func TestCoordinatorPersistsConsensusBeforeDurable(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	if got, want := *consensus.log, []string{"consensus", "durable"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("persistence order=%v, want %v", got, want)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("stores received consensus=%d durable=%d", len(consensus.proposals), len(durable.commits))
	}
}

func TestCoordinatorProposeAndApplyOwnsCASAndPersistence(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := coordinator.ProposeAndApply(context.Background(), Proposal{
		LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 0,
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if commit.State.Revision != 1 || m.Snapshot().Revision != 1 {
		t.Fatalf("commit revision=%d machine revision=%d, want 1/1", commit.State.Revision, m.Snapshot().Revision)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("store calls consensus=%d durable=%d, want 1/1", len(consensus.proposals), len(durable.commits))
	}
	if _, err := coordinator.ProposeAndApply(context.Background(), Proposal{
		LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 0,
		Version: "stale", Payload: []byte(`{"mode":"stale"}`), Nonce: "nonce-stale",
	}); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale CAS error=%v, want ErrStaleRevision", err)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatal("stale proposal reached persistence")
	}
}

func TestCoordinatorProposeAndApplyReturnsExactRetryCommitAfterDurableFailure(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	durable.err = errors.New("postgres unavailable")
	commit, err := coordinator.ProposeAndApply(context.Background(), Proposal{
		LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 0,
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1",
	})
	if err == nil || commit.State.Revision != 1 {
		t.Fatalf("failed proposal result commit=%+v err=%v", commit, err)
	}
	if got := m.Snapshot(); got.Revision != 0 || !got.WriteFrozen {
		t.Fatalf("failed persistence exposed tentative state: %+v", got)
	}
	durable.err = nil
	if err := coordinator.Apply(context.Background(), commit); err != nil {
		t.Fatalf("exact retry failed: %v", err)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("retry duplicated persistence: consensus=%d durable=%d", len(consensus.proposals), len(durable.commits))
	}
}

func TestCoordinatorRetriesOnlyExactCommitAfterConsensusError(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	consensus.err = errors.New("raft result unknown")
	commit, err := coordinator.ProposeAndApply(context.Background(), Proposal{
		LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 0,
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1",
	})
	if err == nil || commit.State.Revision != 1 {
		t.Fatalf("consensus failure result commit=%+v err=%v", commit, err)
	}
	conflict := cloneCommit(commit)
	conflict.State.Desired.Version = "conflicting-v1"
	if err := coordinator.Apply(context.Background(), conflict); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("conflicting retry error=%v, want ErrInvalidCommit", err)
	}
	if len(consensus.proposals) != 0 || len(durable.commits) != 0 {
		t.Fatal("conflicting retry reached persistence")
	}
	consensus.err = nil
	if err := coordinator.Apply(context.Background(), commit); err != nil {
		t.Fatalf("exact retry after unknown consensus result failed: %v", err)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("exact retry persistence consensus=%d durable=%d, want 1/1", len(consensus.proposals), len(durable.commits))
	}
	if got := m.Snapshot(); got.Revision != 1 || !got.WriteFrozen {
		t.Fatalf("exact retry did not install the commit fail-closed: %+v", got)
	}
}

func TestCoordinatorPreCanceledCallsDoNotFreezeHealthyGeneration(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(context.Context, *Coordinator) error
	}{
		{name: "apply", call: func(ctx context.Context, coordinator *Coordinator) error { return coordinator.Apply(ctx, Commit{}) }},
		{name: "propose and apply", call: func(ctx context.Context, coordinator *Coordinator) error {
			_, err := coordinator.ProposeAndApply(ctx, Proposal{})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, coordinator, _, _ := newCoordinatorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := tc.call(ctx, coordinator); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled call error=%v, want context.Canceled", err)
			}
			if got := m.Snapshot(); got.WriteFrozen {
				t.Fatalf("pre-canceled call froze healthy generation: %+v", got)
			}
		})
	}
}

func TestCanceledWaiterDoesNotFreezeInFlightCommit(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	consensus := &blockingConsensus{current: m.Snapshot(), started: make(chan struct{}), release: make(chan struct{})}
	log := make([]string, 0, 1)
	durable := &fakeDurable{log: &log, state: m.Snapshot()}
	coordinator, err := NewCoordinator(m, consensus, durable)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, proposeErr := coordinator.ProposeAndApply(context.Background(), Proposal{
			LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1",
		})
		result <- proposeErr
	}()
	select {
	case <-consensus.started:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight commit did not reach consensus")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coordinator.Apply(canceled, Commit{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error=%v, want context.Canceled", err)
	}
	if got := m.Snapshot(); got.WriteFrozen {
		t.Fatalf("canceled waiter froze in-flight commit: %+v", got)
	}
	close(consensus.release)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("in-flight commit failed after canceled waiter: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight commit did not finish")
	}
}

func TestCompletedCommitRetryFromOldGenerationDoesNotFreezeNewLeader(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := coordinator.ProposeAndApply(context.Background(), Proposal{
		LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(2, "node-b"); err != nil {
		t.Fatal(err)
	}
	consensus.current = m.Snapshot()
	durable.state = m.Snapshot()
	if err := coordinator.Apply(context.Background(), commit); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old-generation retry error=%v, want ErrStaleEpoch", err)
	}
	if got := m.Snapshot(); got.WriteFrozen || got.LeaderID != "node-b" {
		t.Fatalf("old-generation retry froze new leader: %+v", got)
	}
}

func TestCoordinatorDoesNotClaimSuccessWhenEitherStoreFails(t *testing.T) {
	for _, tc := range []struct {
		name         string
		consensusErr error
		durableErr   error
		wantLog      []string
	}{
		{name: "consensus", consensusErr: errors.New("raft down"), wantLog: []string{"consensus"}},
		{name: "durable", durableErr: errors.New("postgres down"), wantLog: []string{"consensus", "durable"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, coordinator, consensus, durable := newCoordinatorFixture(t)
			consensus.err, durable.err = tc.consensusErr, tc.durableErr
			commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
			if err != nil {
				t.Fatal(err)
			}
			if err := coordinator.Apply(context.Background(), commit); err == nil {
				t.Fatal("Apply returned nil despite persistence failure")
			}
			if got := m.Snapshot(); got.Revision != 0 || !got.WriteFrozen {
				t.Fatalf("failed apply exposed state: %+v", got)
			}
			if !reflect.DeepEqual(*consensus.log, tc.wantLog) {
				t.Fatalf("calls=%v, want %v", *consensus.log, tc.wantLog)
			}
		})
	}
}

func TestCoordinatorLoadSnapshotRejectsConsensusDurableMismatch(t *testing.T) {
	m, _ := NewStateMachine("cluster-a", nil)
	consensus := &fakeConsensus{current: State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, Revision: 2}}
	durable := &fakeDurable{state: State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, Revision: 1}}
	c, _ := NewCoordinator(m, consensus, durable)
	if err := c.LoadSnapshot(context.Background()); err == nil {
		t.Fatal("expected mismatch rejection")
	}
}

func TestCoordinatorLoadSnapshotRejectsFreezeStateMismatch(t *testing.T) {
	m, _ := NewStateMachine("cluster-a", nil)
	base := State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, Revision: 1, Desired: DesiredState{Version: "v1", Payload: []byte(`{"enabled":true}`), Digest: Digest([]byte(`{"enabled":true}`))}}
	consensus := &fakeConsensus{current: base}
	durableState := base
	durableState.WriteFrozen = true
	durableState.FreezeReason = "maintenance"
	durable := &fakeDurable{state: durableState}
	c, _ := NewCoordinator(m, consensus, durable)
	if err := c.LoadSnapshot(context.Background()); err == nil {
		t.Fatal("freeze state mismatch was accepted")
	}
}

func TestCoordinatorSupportsFirstCommitWhenDurableStateIsEmpty(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"first":true}`), Nonce: "first"})
	if err != nil {
		t.Fatal(err)
	}
	durable.state = State{}
	durable.loadErr = ErrStateNotFound
	if err := coordinator.Apply(context.Background(), commit); err != nil {
		t.Fatalf("first commit with empty durable state rejected: %v", err)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("store calls=%d/%d", len(consensus.proposals), len(durable.commits))
	}
}

func TestCoordinatorLoadSnapshotAllowsEmptyInitialState(t *testing.T) {
	m, _ := NewStateMachine("cluster-a", nil)
	consensus := &fakeConsensus{current: m.Snapshot()}
	durable := &fakeDurable{loadErr: ErrStateNotFound}
	c, _ := NewCoordinator(m, consensus, durable)
	if err := c.LoadSnapshot(context.Background()); err != nil {
		t.Fatalf("empty initial snapshot rejected: %v", err)
	}
	if state := m.Snapshot(); state.Revision != 0 || !state.WriteFrozen {
		t.Fatalf("initial state changed: %+v", state)
	}
}

func TestCoordinatorRetriesDurableFailureIdempotently(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	durable.err = errors.New("temporary")
	if err := coordinator.Apply(context.Background(), commit); err == nil {
		t.Fatal("first Apply returned nil")
	}
	durable.err = nil
	if err := coordinator.Apply(context.Background(), commit); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if err := coordinator.Apply(context.Background(), commit); err != nil {
		t.Fatalf("duplicate successful Apply failed: %v", err)
	}
	if len(durable.commits) != 1 {
		t.Fatalf("durable commits=%d, want 1", len(durable.commits))
	}
	if len(consensus.proposals) != 1 {
		t.Fatalf("consensus proposals=%d, want 1", len(consensus.proposals))
	}
}

func TestCoordinatorRetryKeepsStateFrozenUntilExplicitResume(t *testing.T) {
	m, coordinator, _, durable := newCoordinatorFixture(t)
	first, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"n":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	durable.err = errors.New("temporary")
	if err := coordinator.Apply(context.Background(), first); err == nil {
		t.Fatal("first Apply returned nil")
	}
	durable.err = nil
	if err := coordinator.Apply(context.Background(), first); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	state := m.Snapshot()
	if !state.WriteFrozen || state.Revision != 1 {
		t.Fatalf("successful retry unexpectedly unfroze state: %+v", state)
	}
	wrongFence := first.Fence
	wrongFence.Digest = Digest([]byte(`{"wrong":true}`))
	if err := coordinator.ResumeWrites(context.Background(), wrongFence); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("unbound resume authority accepted: %v", err)
	}
	if err := coordinator.ResumeWrites(context.Background(), first.Fence); err != nil {
		t.Fatalf("explicit resume failed: %v", err)
	}
	if _, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"n":2}`), Nonce: "nonce-2"}); err != nil {
		t.Fatalf("next proposal rejected after retry: %v", err)
	}
}

func TestCoordinatorRejectsUnboundCommit(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	commit.Fence.Digest = Digest([]byte(`{"tampered":true}`))
	if err := coordinator.Apply(context.Background(), commit); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("error=%v, want ErrInvalidCommit", err)
	}
	if len(consensus.proposals) != 0 || len(durable.commits) != 0 {
		t.Fatal("unbound commit reached a store")
	}
	commit, err = m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"mode":"enforce"}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	commit.Fence.Nonce = "wrong-nonce"
	if err := coordinator.Apply(context.Background(), commit); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("nonce tamper error=%v, want ErrInvalidCommit", err)
	}
}

func TestCoordinatorLoadsSnapshotAndContinuesCAS(t *testing.T) {
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"enabled":true}`)
	state := State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 4, Epoch: 2, Revision: 7, UpdatedAt: time.Now().UTC(), Desired: DesiredState{Version: "v7", Payload: payload, Digest: Digest(payload)}, NonceLedger: map[string]Revision{"n1": 1, "n2": 2, "n3": 3, "n4": 4, "n5": 5, "n6": 6, "n7": 7}}
	consensus := &fakeConsensus{current: state}
	durable := &fakeDurable{state: state}
	coordinator, err := NewCoordinator(m, consensus, durable)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.LoadSnapshot(context.Background()); err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}
	if err := m.ResumeWrites(FenceToken{ClusterID: "cluster-a", LeaderID: "node-a", Epoch: 2, Revision: 7, Digest: state.Desired.Digest, Nonce: "n7"}); err != nil {
		t.Fatalf("resume after snapshot failed: %v", err)
	}
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 2, ExpectedRevision: 7, Version: "v8", Payload: []byte(`{"enabled":false}`), Nonce: "nonce-8"})
	if err != nil {
		t.Fatalf("CAS after snapshot failed: %v", err)
	}
	if commit.State.Revision != 8 {
		t.Fatalf("revision=%d, want 8", commit.State.Revision)
	}
}

func TestCoordinatorLoadSnapshotUsesPostgresTimestampPrecision(t *testing.T) {
	payload := []byte(`{"enabled":true}`)
	consensusState := State{
		ClusterID: "cluster-a", LeaderID: "node-a", Term: 4, Epoch: 2, Revision: 1,
		UpdatedAt: time.Date(2026, 9, 22, 12, 0, 0, 123456789, time.UTC),
		Desired:   DesiredState{Version: "v1", Payload: payload, Digest: Digest(payload)},
		NonceLedger: map[string]Revision{
			"nonce-1": 1,
		},
	}

	for _, test := range []struct {
		name    string
		durable time.Time
		wantErr bool
	}{
		{name: "postgres microsecond round trip", durable: consensusState.UpdatedAt.Truncate(time.Microsecond)},
		{name: "different durable microsecond", durable: consensusState.UpdatedAt.Truncate(time.Microsecond).Add(time.Microsecond), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			machine, err := NewStateMachine(consensusState.ClusterID, nil)
			if err != nil {
				t.Fatal(err)
			}
			durableState := consensusState
			durableState.UpdatedAt = test.durable
			coordinator, err := NewCoordinator(machine, &fakeConsensus{current: consensusState}, &fakeDurable{state: durableState})
			if err != nil {
				t.Fatal(err)
			}
			err = coordinator.LoadSnapshot(context.Background())
			if test.wantErr {
				if !errors.Is(err, ErrInvalidCommit) {
					t.Fatalf("LoadSnapshot error=%v, want ErrInvalidCommit", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadSnapshot rejected PostgreSQL timestamp precision: %v", err)
			}
		})
	}
}

func TestCoordinatorRejectsOldEpochTokenButAllowsCurrentEpochRetry(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	first, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"n":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"n":2}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(context.Background(), first); err != nil {
		t.Fatalf("historical current-epoch commit rejected: %v", err)
	}
	if err := coordinator.Apply(context.Background(), second); err != nil {
		t.Fatalf("current commit rejected: %v", err)
	}
	if len(consensus.proposals) != 2 || len(durable.commits) != 2 {
		t.Fatalf("store calls consensus=%d durable=%d, want 2/2", len(consensus.proposals), len(durable.commits))
	}

	if _, err := m.InstallLeadership(2, "node-b"); err != nil {
		t.Fatal(err)
	}
	beforeConsensus, beforeDurable := len(consensus.proposals), len(durable.commits)
	if err := coordinator.Apply(context.Background(), first); !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("old epoch apply error=%v, want ErrStaleEpoch", err)
	}
	if len(consensus.proposals) != beforeConsensus || len(durable.commits) != beforeDurable {
		t.Fatal("old epoch token reached a store")
	}
}

func TestHistoricalCommitInstallDoesNotRollbackTentativeState(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	first, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"n":1}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"n":2}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if got := m.Snapshot(); got.Revision != 1 {
		t.Fatalf("historical install exposed revision %d, want 1", got.Revision)
	}
	durable.state = second.State
	consensus.current = second.State
	if err := coordinator.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if got := m.Snapshot(); got.Revision != 2 || got.Desired.Version != "v2" {
		t.Fatalf("current commit did not become committed: %+v", got)
	}
}

func TestCoordinatorFreezesWhenDurableBaselineLoadFails(t *testing.T) {
	m, coordinator, _, durable := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	durable.loadErr = errors.New("postgres baseline unavailable")
	if err := coordinator.Apply(context.Background(), commit); err == nil {
		t.Fatal("Apply accepted durable baseline failure")
	}
	if got := m.Snapshot(); !got.WriteFrozen || got.Revision != 0 {
		t.Fatalf("durable baseline failure did not freeze state: %+v", got)
	}
}

func TestCoordinatorPreflightCancellationDoesNotFreezeWrites(t *testing.T) {
	m, coordinator, _, _ := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := coordinator.Apply(ctx, commit); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Apply error=%v, want context.Canceled", err)
	}
	if got := m.Snapshot(); got.WriteFrozen {
		t.Fatalf("preflight-canceled Apply froze state: %+v", got)
	}
}

func TestCoordinatorRejectsDurableCommitMissingFromConsensus(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	commit, err := m.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "nonce-1"})
	if err != nil {
		t.Fatal(err)
	}
	durable.state = commit.State
	if err := coordinator.Apply(context.Background(), commit); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("durable-only commit error=%v, want ErrInvalidCommit", err)
	}
	if len(consensus.proposals) != 0 || len(durable.commits) != 0 {
		t.Fatal("divergent durable-only commit reached a persistence stage")
	}
	if got := m.Snapshot(); !got.WriteFrozen || got.Revision != 0 {
		t.Fatalf("durable-only divergence did not remain fail-closed: %+v", got)
	}
}

func TestCoordinatorRejectsTypedNilDependencies(t *testing.T) {
	var consensus *fakeConsensus
	durable := &fakeDurable{}
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCoordinator(machine, consensus, durable); !errors.Is(err, ErrInvalidCommit) {
		t.Fatalf("typed nil consensus accepted: %v", err)
	}
}

func TestStateMachineRequiresLeaderAndEpochToResumeWrites(t *testing.T) {
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
	m.FreezeWrites("maintenance")
	wrongEpoch := commit.Fence
	wrongEpoch.Epoch++
	if err := m.ResumeWrites(wrongEpoch); !errors.Is(err, ErrWritesFrozen) {
		t.Fatalf("wrong epoch resume error=%v", err)
	}
	wrongLeader := commit.Fence
	wrongLeader.LeaderID = "node-b"
	if err := m.ResumeWrites(wrongLeader); !errors.Is(err, ErrWritesFrozen) {
		t.Fatalf("wrong leader resume error=%v", err)
	}
	if err := m.ResumeWrites(commit.Fence); err != nil {
		t.Fatalf("bound resume failed: %v", err)
	}
	if got := m.Snapshot(); got.WriteFrozen {
		t.Fatalf("bound resume left writes frozen: %+v", got)
	}
}

func TestCoordinatorInitializeRequiresExplicitConfirmationAndPersistsFirstCommit(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	m.FreezeWrites("control-plane startup incomplete")
	request := InitialStateRequest{Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-1", Confirmation: InitialStateConfirmation{ID: "confirmation-1", Actor: "admin", Reason: "initialize cluster"}}
	commit, err := coordinator.Initialize(context.Background(), request)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if commit.State.Revision != 1 || len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("initial commit=%+v stores=%d/%d", commit, len(consensus.proposals), len(durable.commits))
	}
	if got := m.Snapshot(); got.Revision != 1 || !got.WriteFrozen {
		t.Fatalf("Initialize should retain startup freeze until explicit resume: %+v", got)
	}
}

func TestCoordinatorInitializePreservesCurrentLeadershipGeneration(t *testing.T) {
	m, coordinator, consensus, durable := newCoordinatorFixture(t)
	if _, err := m.InstallLeadership(2, "node-b"); err != nil {
		t.Fatal(err)
	}
	m.FreezeWrites("control-plane startup incomplete")
	current := m.Snapshot()
	consensus.current = current
	durable.state = current
	request := InitialStateRequest{
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-epoch-2",
		Confirmation: InitialStateConfirmation{ID: "confirmation-epoch-2", Actor: "admin"},
	}
	commit, err := coordinator.Initialize(context.Background(), request)
	if err != nil {
		t.Fatalf("Initialize at epoch %d failed: %v", current.Epoch, err)
	}
	if commit.State.Term != current.Term || commit.State.Epoch != current.Epoch || commit.State.LeaderID != current.LeaderID {
		t.Fatalf("initial commit leadership=%+v, want term=%d epoch=%d leader=%q", commit.State, current.Term, current.Epoch, current.LeaderID)
	}
	if len(consensus.proposals) != 1 || len(durable.commits) != 1 {
		t.Fatalf("initial commit stores=%d/%d, want one each", len(consensus.proposals), len(durable.commits))
	}
}

func TestCoordinatorInitializeRejectsMissingConfirmation(t *testing.T) {
	_, coordinator, _, _ := newCoordinatorFixture(t)
	_, err := coordinator.Initialize(context.Background(), InitialStateRequest{Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-1"})
	if err == nil || !errors.Is(err, ErrStartupInitialState) {
		t.Fatalf("unconfirmed Initialize error=%v, want ErrStartupInitialState", err)
	}
}
