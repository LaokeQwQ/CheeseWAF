package controlplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type startupDurableFake struct {
	state       State
	err         error
	loadErr     error
	log         *[]string
	loaded      bool
	backend     string
	cancel      func()
	checkpoints int
	append      func(Commit)
}

func (f *startupDurableFake) Backend() string {
	if f.backend != "" {
		return f.backend
	}
	return "postgresql"
}

func (f *startupDurableFake) Prepare(context.Context) error {
	*f.log = append(*f.log, "durable.prepare")
	if f.cancel != nil {
		f.cancel()
		return context.Canceled
	}
	return f.err
}

func (f *startupDurableFake) Health(context.Context) error {
	*f.log = append(*f.log, "durable.health")
	return f.err
}

func (f *startupDurableFake) LoadState(context.Context, string) (State, error) {
	*f.log = append(*f.log, "durable.load")
	if f.err != nil {
		return State{}, f.err
	}
	if f.loadErr != nil {
		return State{}, f.loadErr
	}
	f.loaded = true
	return f.state, nil
}

func (f *startupDurableFake) AppendCommit(_ context.Context, commit Commit) error {
	if f.append != nil {
		f.append(commit)
	}
	return nil
}

func (f *startupDurableFake) CheckpointLeadership(_ context.Context, state State) error {
	f.checkpoints++
	f.state = state
	if f.log != nil {
		*f.log = append(*f.log, "durable.checkpoint")
	}
	return nil
}

type startupConsensusFake struct {
	state   State
	err     error
	log     *[]string
	backend string
	states  []State
	index   int
}

func (f *startupConsensusFake) Backend() string {
	if f.backend != "" {
		return f.backend
	}
	return "native-raft"
}

func (f *startupConsensusFake) Prepare(context.Context) error {
	*f.log = append(*f.log, "consensus.prepare")
	return f.err
}

func (f *startupConsensusFake) Health(context.Context) error {
	*f.log = append(*f.log, "consensus.health")
	return f.err
}

func (f *startupConsensusFake) Current(context.Context, string) (State, error) {
	*f.log = append(*f.log, "consensus.current")
	if f.err != nil {
		return State{}, f.err
	}
	if len(f.states) > 0 {
		state := f.states[f.index]
		if f.index < len(f.states)-1 {
			f.index++
		}
		return state, nil
	}
	return f.state, nil
}

func (f *startupConsensusFake) Propose(_ context.Context, commit Commit) error {
	f.state = commit.State
	return nil
}

type startupFenceFake struct {
	log         *[]string
	token       FenceToken
	err         error
	onEstablish func(State)
}

func (f *startupFenceFake) Establish(_ context.Context, state State) (FenceToken, error) {
	*f.log = append(*f.log, "fence.establish")
	if f.onEstablish != nil {
		f.onEstablish(state)
	}
	return f.token, f.err
}

func startupCommittedState(t *testing.T) (*StateMachine, State, FenceToken) {
	t.Helper()
	m, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.InstallLeadership(1, "node-a"); err != nil {
		t.Fatal(err)
	}
	commit, err := m.Propose(Proposal{
		LeaderID:      "node-a",
		ExpectedEpoch: 1,
		Version:       "v1",
		Payload:       []byte(`{"mode":"observe"}`),
		Nonce:         "nonce-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	m.InstallCommit(commit)
	return m, m.Snapshot(), commit.Fence
}

func TestBootstrapProductionOrdersDurableConsensusSnapshotAndFence(t *testing.T) {
	_, state, fence := startupCommittedState(t)
	log := []string{}
	durable := &startupDurableFake{state: state, log: &log}
	consensus := &startupConsensusFake{state: state, log: &log}
	fencer := &startupFenceFake{token: fence, log: &log}
	machine, _, _ := startupCommittedState(t)
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile:   StorageProfileProduction,
		ClusterID: "cluster-a",
		Machine:   machine,
		Durable:   durable,
		Consensus: consensus,
		Fencer:    fencer,
	})
	if err != nil {
		t.Fatalf("Bootstrap failed: %v", err)
	}
	if !result.Ready || result.Stage != StartupStageReady {
		t.Fatalf("result=%+v, want ready", result)
	}
	want := []string{"durable.prepare", "durable.health", "durable.load", "consensus.prepare", "consensus.health", "consensus.current", "fence.establish", "consensus.current"}
	if !reflect.DeepEqual(log, want) {
		t.Fatalf("startup order=%v, want %v", log, want)
	}
	if result.Fence != fence || result.State.Revision != 1 {
		t.Fatalf("result=%+v, want committed revision and fence", result)
	}
	if result.Coordinator == nil {
		t.Fatal("ready production startup must return a coordinator")
	}
}

func TestBootstrapProductionFailsClosedBeforeConsensusWhenDurableUnavailable(t *testing.T) {
	machine, _, _ := startupCommittedState(t)
	log := []string{}
	durableErr := errors.New("postgres unavailable")
	durable := &startupDurableFake{err: durableErr, log: &log}
	consensus := &startupConsensusFake{log: &log}
	fencer := &startupFenceFake{log: &log}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile:   StorageProfileProduction,
		ClusterID: "cluster-a",
		Machine:   machine,
		Durable:   durable,
		Consensus: consensus,
		Fencer:    fencer,
	})
	if err == nil || !errors.Is(err, durableErr) {
		t.Fatalf("error=%v, want durable error", err)
	}
	if result.Ready || result.Stage != StartupStageDurable {
		t.Fatalf("result=%+v, want durable failure", result)
	}
	if !reflect.DeepEqual(log, []string{"durable.prepare"}) {
		t.Fatalf("startup continued after durable failure: %v", log)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.Revision != 1 {
		t.Fatalf("last-known-good was not frozen safely: %+v", got)
	}
}

func TestBootstrapProductionRejectsDivergentSnapshotsAndKeepsLastKnownGood(t *testing.T) {
	machine, state, fence := startupCommittedState(t)
	diverged := state
	diverged.Revision++
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile:   StorageProfileProduction,
		ClusterID: "cluster-a",
		Machine:   machine,
		Durable:   &startupDurableFake{state: state, log: &log},
		Consensus: &startupConsensusFake{state: diverged, log: &log},
		Fencer:    &startupFenceFake{token: fence, log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupDiverged) {
		t.Fatalf("error=%v, want divergent snapshot error", err)
	}
	if result.Ready || result.Stage != StartupStageSnapshot {
		t.Fatalf("result=%+v, want snapshot failure", result)
	}
	if machine.Snapshot().Revision != 1 || !machine.Snapshot().WriteFrozen {
		t.Fatalf("last-known-good snapshot was not retained safely: %+v", machine.Snapshot())
	}
}

func TestBootstrapProductionFailsClosedWhenFencingCannotBeEstablished(t *testing.T) {
	machine, state, _ := startupCommittedState(t)
	log := []string{}
	fenceErr := errors.New("native raft fence unavailable")
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile:   StorageProfileProduction,
		ClusterID: "cluster-a",
		Machine:   machine,
		Durable:   &startupDurableFake{state: state, log: &log},
		Consensus: &startupConsensusFake{state: state, log: &log},
		Fencer:    &startupFenceFake{err: fenceErr, log: &log},
	})
	if err == nil || !errors.Is(err, fenceErr) {
		t.Fatalf("error=%v, want fence error", err)
	}
	if result.Ready || result.Stage != StartupStageFencing {
		t.Fatalf("result=%+v, want fencing failure", result)
	}
	got := machine.Snapshot()
	if got.Revision != 1 || !got.WriteFrozen || got.Desired.Digest == "" {
		t.Fatalf("last-known-good desired state was not retained: %+v", got)
	}
}

func TestBootstrapProductionRejectsUnboundFenceOnEmptySnapshot(t *testing.T) {
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	initial := emptyStartupState("cluster-a")
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile:   StorageProfileProduction,
		ClusterID: "cluster-a",
		Machine:   machine,
		Durable:   &startupDurableFake{state: initial, log: &log},
		Consensus: &startupConsensusFake{state: initial, log: &log},
		Fencer:    &startupFenceFake{log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupFencing) {
		t.Fatalf("error=%v, want fencing readiness failure", err)
	}
	if result.Ready || result.Stage != StartupStageFencing {
		t.Fatalf("result=%+v, want fencing failure", result)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.Revision != 0 {
		t.Fatalf("empty production snapshot must remain frozen: %+v", got)
	}
}

func TestBootstrapRejectsTemporaryProfileAndMissingProductionBoundaries(t *testing.T) {
	machine, _, _ := startupCommittedState(t)
	base := StartupOptions{Profile: StorageProfileTemporary, ClusterID: "cluster-a", Machine: machine}
	if _, err := Bootstrap(context.Background(), base); err == nil || !strings.Contains(err.Error(), "temporary") {
		t.Fatalf("temporary profile unexpectedly accepted: %v", err)
	}
	base.Profile = StorageProfileProduction
	if _, err := Bootstrap(context.Background(), base); err == nil || !errors.Is(err, ErrStartupContract) {
		t.Fatalf("missing production boundaries accepted: %v", err)
	}
}

func TestBootstrapRejectsCompatibilityBackendsBeforePreparingThem(t *testing.T) {
	for _, tc := range []struct {
		name             string
		durableBackend   string
		consensusBackend string
	}{
		{name: "SQLite", durableBackend: "sqlite"},
		{name: "builtin", consensusBackend: "builtin"},
		{name: "etcd", consensusBackend: "etcd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			machine, state, fence := startupCommittedState(t)
			log := []string{}
			_, err := Bootstrap(context.Background(), StartupOptions{
				Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
				Durable:   &startupDurableFake{state: state, log: &log, backend: tc.durableBackend},
				Consensus: &startupConsensusFake{state: state, log: &log, backend: tc.consensusBackend},
				Fencer:    &startupFenceFake{token: fence, log: &log},
			})
			if !errors.Is(err, ErrStartupContract) {
				t.Fatalf("compatibility backend accepted: %v", err)
			}
			if len(log) != 0 {
				t.Fatalf("invalid backend performed startup operations: %v", log)
			}
		})
	}
}

func TestBootstrapFreezesExistingStateWhenProductionContractIsInvalid(t *testing.T) {
	machine, _, _ := startupCommittedState(t)
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: " cluster-a", Machine: machine,
		Durable: &startupDurableFake{log: &log}, Consensus: &startupConsensusFake{log: &log}, Fencer: &startupFenceFake{log: &log},
	})
	if !errors.Is(err, ErrStartupContract) || result.Ready || result.Stage != StartupStageContract {
		t.Fatalf("invalid contract result=%+v, error=%v", result, err)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.Revision != 1 || got.Desired.Digest == "" {
		t.Fatalf("existing last-known-good state was not frozen: %+v", got)
	}
	if len(log) != 0 {
		t.Fatalf("invalid contract performed startup operations: %v", log)
	}
}

func TestBootstrapKeepsWritesFrozenAndLastKnownGoodUntilFenceIsVerified(t *testing.T) {
	machine, previous, _ := startupCommittedState(t)
	upstream, _, _ := startupCommittedState(t)
	commit, err := upstream.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"mode":"enforce"}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	upstream.InstallCommit(commit)
	state := upstream.Snapshot()
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable:   &startupDurableFake{state: state, log: &log},
		Consensus: &startupConsensusFake{state: state, log: &log},
		Fencer: &startupFenceFake{token: commit.Fence, log: &log, onEstablish: func(State) {
			got := machine.Snapshot()
			if !got.WriteFrozen || got.Desired.Digest != previous.Desired.Digest {
				t.Errorf("unverified startup state became visible: %+v", got)
			}
		}},
	})
	if err != nil || !result.Ready || result.State.Revision != 2 {
		t.Fatalf("bootstrap=%+v, error=%v", result, err)
	}
}

func TestBootstrapRejectsWhitespaceAndInvisibleClusterIDs(t *testing.T) {
	for _, id := range []string{" cluster-a", "cluster-a ", "cluster-\u200b-a", "cluster-\n-a"} {
		t.Run(id, func(t *testing.T) {
			machine, _, _ := startupCommittedState(t)
			_, err := Bootstrap(context.Background(), StartupOptions{
				Profile: StorageProfileProduction, ClusterID: id, Machine: machine,
				Durable: &startupDurableFake{}, Consensus: &startupConsensusFake{}, Fencer: &startupFenceFake{},
			})
			if !errors.Is(err, ErrStartupContract) {
				t.Fatalf("cluster ID %q accepted: %v", id, err)
			}
		})
	}
}

func TestBootstrapFreezesWhenContextIsCanceledBeforeValidationCompletes(t *testing.T) {
	machine, _, _ := startupCommittedState(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Bootstrap(ctx, StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable: &startupDurableFake{}, Consensus: &startupConsensusFake{}, Fencer: &startupFenceFake{},
	})
	if err == nil || !errors.Is(err, ErrStartupContract) || result.Ready {
		t.Fatalf("pre-canceled startup accepted: result=%+v error=%v", result, err)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.Revision != 1 {
		t.Fatalf("pre-canceled startup did not preserve frozen LKG: %+v", got)
	}
}

func TestBootstrapRejectsLeadershipChangeAfterFencing(t *testing.T) {
	machine, state, fence := startupCommittedState(t)
	changed := state
	changed.Term = 2
	changed.Epoch = 2
	changed.LeaderID = "node-b"
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable:   &startupDurableFake{state: state, log: &log},
		Consensus: &startupConsensusFake{states: []State{state, changed}, log: &log},
		Fencer:    &startupFenceFake{token: fence, log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupFencing) || result.Ready {
		t.Fatalf("leadership changed after fencing was accepted: result=%+v error=%v", result, err)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.Desired.Digest != state.Desired.Digest {
		t.Fatalf("leadership race did not preserve LKG: %+v", got)
	}
}

func TestBootstrapCASRejectsLocalLeadershipChangeBeforeSnapshotInstall(t *testing.T) {
	machine, state, fence := startupCommittedState(t)
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable:   &startupDurableFake{state: state, log: &log},
		Consensus: &startupConsensusFake{state: state, log: &log},
		Fencer: &startupFenceFake{token: fence, log: &log, onEstablish: func(State) {
			if _, err := machine.InstallLeadership(2, "node-b"); err != nil {
				t.Errorf("leadership mutation failed: %v", err)
			}
		}},
	})
	if err == nil || !errors.Is(err, ErrStartupDiverged) || result.Ready {
		t.Fatalf("local leadership change was not rejected: result=%+v error=%v", result, err)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.LeaderID != "node-b" {
		t.Fatalf("post-fence leadership state was not preserved fail-closed: %+v", got)
	}
}

func TestBootstrapRejectsSameRevisionConflictWithLocalLastKnownGood(t *testing.T) {
	machine, previous, _ := startupCommittedState(t)
	incomingMachine, incoming, fence := startupCommittedState(t)
	commit, err := incomingMachine.Propose(Proposal{LeaderID: "node-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: "v2", Payload: []byte(`{"mode":"enforce"}`), Nonce: "nonce-2"})
	if err != nil {
		t.Fatal(err)
	}
	// Keep the incoming snapshot at revision 1 while changing its content.
	incoming = commit.State
	incoming.Revision = previous.Revision
	incoming.NonceLedger = map[string]Revision{commit.Fence.Nonce: previous.Revision}
	fence = commit.Fence
	fence.Revision = previous.Revision
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable:   &startupDurableFake{state: incoming, log: &log},
		Consensus: &startupConsensusFake{state: incoming, log: &log},
		Fencer:    &startupFenceFake{token: fence, log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupDiverged) || result.Ready {
		t.Fatalf("conflicting same-revision snapshot accepted: result=%+v error=%v", result, err)
	}
	got := machine.Snapshot()
	if got.Desired.Digest != previous.Desired.Digest || !got.WriteFrozen {
		t.Fatalf("local last-known-good was replaced: %+v", got)
	}
}

func TestBootstrapStopsBeforeSnapshotLoadWhenContextIsCanceled(t *testing.T) {
	machine, state, fence := startupCommittedState(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := []string{}
	result, err := Bootstrap(ctx, StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable:   &startupDurableFake{state: state, log: &log, cancel: cancel},
		Consensus: &startupConsensusFake{state: state, log: &log},
		Fencer:    &startupFenceFake{token: fence, log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupDurable) || result.Ready {
		t.Fatalf("canceled startup accepted: result=%+v error=%v", result, err)
	}
	if !reflect.DeepEqual(log, []string{"durable.prepare"}) {
		t.Fatalf("startup continued after context cancellation: %v", log)
	}
}

func TestBootstrapRequiresProtectedInitialStateForBothEmptySnapshots(t *testing.T) {
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable:   &startupDurableFake{log: &log, loadErr: ErrStateNotFound},
		Consensus: &startupConsensusFake{log: &log, state: emptyStartupState("cluster-a")},
		Fencer:    &startupFenceFake{log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupInitialState) || !errors.Is(err, ErrStartupFencing) {
		t.Fatalf("empty startup error=%v, want protected initial-state and fencing errors", err)
	}
	if result.Ready || result.Stage != StartupStageFencing {
		t.Fatalf("empty startup result=%+v, want frozen fencing failure", result)
	}
	if got := machine.Snapshot(); !got.WriteFrozen || got.Revision != 0 {
		t.Fatalf("empty startup was not frozen: %+v", got)
	}
}

func TestBootstrapInitialStateRequiresAdministratorConfirmation(t *testing.T) {
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &InitialStateRequest{Version: "v1", Payload: []byte(`{"mode":"observe"}`)}
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine, InitialState: request,
		Durable:   &startupDurableFake{log: &log, loadErr: ErrStateNotFound},
		Consensus: &startupConsensusFake{log: &log, state: emptyStartupState("cluster-a")},
		Fencer:    &startupFenceFake{log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupInitialState) || result.Ready {
		t.Fatalf("unconfirmed initial state accepted: result=%+v err=%v", result, err)
	}
}

func TestBootstrapCreatesFirstCommitOnlyAfterProtectedConfirmation(t *testing.T) {
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, WriteFrozen: false}
	request := &InitialStateRequest{Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-1", Confirmation: InitialStateConfirmation{ID: "confirmation-1", Actor: "admin", Reason: "initialize cluster"}}
	log := []string{}
	consensus := &startupConsensusFake{state: leader, log: &log}
	durable := &startupDurableFake{log: &log, loadErr: ErrStateNotFound}
	var committed State
	durable.append = func(c Commit) { committed = c.State }
	fencer := &startupFenceFake{log: &log}
	fencer.onEstablish = func(state State) { fencer.token = fenceForState(state) }
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine, InitialState: request,
		InitialAuthorizer: startupInitialAuthorizerFunc(func(context.Context, InitialStateRequest) error { return nil }),
		Durable:           durable, Consensus: consensus, Fencer: fencer,
	})
	if err != nil || !result.Ready {
		t.Fatalf("confirmed initial bootstrap failed: result=%+v err=%v", result, err)
	}
	if committed.Revision != 1 || committed.Desired.Digest != Digest(request.Payload) {
		t.Fatalf("durable first commit=%+v, want revision 1 and payload digest", committed)
	}
	if result.Fence.Nonce != request.Nonce || result.State.Revision != 1 || result.State.WriteFrozen {
		t.Fatalf("confirmed initial state result=%+v, want writable revision 1", result)
	}
}

func TestBootstrapRejectsCompleteInitialStateWithoutExternalAuthorizer(t *testing.T) {
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &InitialStateRequest{Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-no-authorizer", Confirmation: InitialStateConfirmation{ID: "confirmation-no-authorizer", Actor: "admin", Reason: "initialize cluster"}}
	log := []string{}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine, InitialState: request,
		Durable:   &startupDurableFake{log: &log, loadErr: ErrStateNotFound},
		Consensus: &startupConsensusFake{log: &log, state: State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1}},
		Fencer:    &startupFenceFake{log: &log},
	})
	if err == nil || !errors.Is(err, ErrStartupInitialState) || result.Ready {
		t.Fatalf("initial state without external authorizer accepted: result=%+v err=%v", result, err)
	}
}

func TestBootstrapInitialStateCallsExternalAuthorizerBeforePersistence(t *testing.T) {
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	leader := State{ClusterID: "cluster-a", LeaderID: "node-a", Term: 1, Epoch: 1, WriteFrozen: false}
	request := &InitialStateRequest{Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-2", Confirmation: InitialStateConfirmation{ID: "confirmation-2", Actor: "admin"}}
	log := []string{}
	consensus := &startupConsensusFake{state: leader, log: &log}
	durable := &startupDurableFake{log: &log, loadErr: ErrStateNotFound}
	fencer := &startupFenceFake{log: &log}
	fencer.onEstablish = func(state State) { fencer.token = fenceForState(state) }
	authorizer := startupInitialAuthorizerFunc(func(_ context.Context, got InitialStateRequest) error {
		if got.Confirmation.ID != request.Confirmation.ID {
			t.Fatalf("authorizer request=%+v", got)
		}
		log = append(log, "initial.authorize")
		return nil
	})
	if _, err := Bootstrap(context.Background(), StartupOptions{Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine, InitialState: request, InitialAuthorizer: authorizer, Durable: durable, Consensus: consensus, Fencer: fencer}); err != nil {
		t.Fatalf("authorized initial bootstrap failed: %v", err)
	}
	if !containsString(log, "initial.authorize") {
		t.Fatalf("authorizer order=%v", log)
	}
}

func TestBootstrapRecoversInitialCommitFromConsensusIntoMissingDurableStore(t *testing.T) {
	_, committed, _ := startupCommittedState(t)
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &InitialStateRequest{Version: committed.Desired.Version, Payload: append([]byte(nil), committed.Desired.Payload...), Digest: committed.Desired.Digest, Nonce: "nonce-1", Confirmation: InitialStateConfirmation{ID: "confirmation-recover-1", Actor: "admin", Reason: "recover initial commit"}}
	log := []string{}
	durable := &startupDurableFake{log: &log, loadErr: ErrStateNotFound}
	var appended Commit
	durable.append = func(commit Commit) { appended = commit }
	consensus := &startupConsensusFake{state: committed, log: &log}
	fencer := &startupFenceFake{log: &log}
	fencer.onEstablish = func(state State) { fencer.token = fenceForState(state) }
	authorized := 0
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable: durable, Consensus: consensus, Fencer: fencer, InitialState: request,
		InitialAuthorizer: startupInitialAuthorizerFunc(func(context.Context, InitialStateRequest) error { authorized++; return nil }),
	})
	if err != nil || !result.Ready {
		t.Fatalf("consensus-side recovery failed: result=%+v err=%v", result, err)
	}
	if authorized != 1 || appended.State.Revision != 1 || appended.Fence.Nonce != request.Nonce || appended.State.Desired.Digest != request.Digest {
		t.Fatalf("recovery authorization/appended commit mismatch: authorized=%d commit=%+v", authorized, appended)
	}
}

func TestBootstrapRecoversInitialCommitFromDurableIntoLeaderOnlyConsensus(t *testing.T) {
	_, committed, _ := startupCommittedState(t)
	leader := State{ClusterID: "cluster-a", LeaderID: "node-b", Term: 2, Epoch: 2, WriteFrozen: false}
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &InitialStateRequest{Version: committed.Desired.Version, Payload: append([]byte(nil), committed.Desired.Payload...), Digest: committed.Desired.Digest, Nonce: "nonce-1", Confirmation: InitialStateConfirmation{ID: "confirmation-recover-2", Actor: "admin", Reason: "recover initial commit"}}
	log := []string{}
	durable := &startupDurableFake{state: committed, log: &log}
	consensus := &startupConsensusFake{state: leader, log: &log}
	checkpoint := &startupCheckpointFake{log: &log}
	fencer := &startupFenceFake{log: &log}
	fencer.onEstablish = func(state State) { fencer.token = fenceForState(state) }
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable: durable, Consensus: consensus, Fencer: fencer, InitialState: request,
		InitialAuthorizer:    startupInitialAuthorizerFunc(func(context.Context, InitialStateRequest) error { return nil }),
		LeadershipCheckpoint: checkpoint,
	})
	if err != nil || !result.Ready {
		t.Fatalf("durable-side recovery failed: result=%+v err=%v", result, err)
	}
	if consensus.state.Revision != 1 || consensus.state.LeaderID != leader.LeaderID || consensus.state.Term != leader.Term || consensus.state.Desired.Digest != committed.Desired.Digest {
		t.Fatalf("consensus recovery changed payload or leadership: %+v", consensus.state)
	}
	if checkpoint.calls != 1 || durable.checkpoints != 1 {
		t.Fatalf("leadership checkpoint calls=%d durable=%d", checkpoint.calls, durable.checkpoints)
	}
}

func TestBootstrapSingleSideInitialCommitRecoveryRequiresExternalAuthorizer(t *testing.T) {
	_, committed, _ := startupCommittedState(t)
	request := &InitialStateRequest{Version: committed.Desired.Version, Payload: append([]byte(nil), committed.Desired.Payload...), Digest: committed.Desired.Digest, Nonce: "nonce-1", Confirmation: InitialStateConfirmation{ID: "confirmation-recover-required", Actor: "admin", Reason: "recover initial commit"}}

	t.Run("consensus-only", func(t *testing.T) {
		machine, err := NewStateMachine("cluster-a", nil)
		if err != nil {
			t.Fatal(err)
		}
		log := []string{}
		appended := 0
		result, err := Bootstrap(context.Background(), StartupOptions{
			Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
			Durable:   &startupDurableFake{loadErr: ErrStateNotFound, log: &log, append: func(Commit) { appended++ }},
			Consensus: &startupConsensusFake{state: committed, log: &log}, Fencer: &startupFenceFake{log: &log},
			InitialState: request,
		})
		if err == nil || !errors.Is(err, ErrStartupInitialState) || result.Ready || appended != 0 {
			t.Fatalf("consensus-only recovery without external authorizer: result=%+v err=%v appended=%d", result, err, appended)
		}
	})

	t.Run("durable-only", func(t *testing.T) {
		machine, err := NewStateMachine("cluster-a", nil)
		if err != nil {
			t.Fatal(err)
		}
		log := []string{}
		leader := State{ClusterID: "cluster-a", LeaderID: "node-b", Term: 2, Epoch: 2, WriteFrozen: false}
		consensus := &startupConsensusFake{state: leader, log: &log}
		result, err := Bootstrap(context.Background(), StartupOptions{
			Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
			Durable: &startupDurableFake{state: committed, log: &log}, Consensus: consensus,
			Fencer: &startupFenceFake{log: &log}, InitialState: request,
		})
		if err == nil || !errors.Is(err, ErrStartupInitialState) || result.Ready || consensus.state.Revision != 0 {
			t.Fatalf("durable-only recovery without external authorizer: result=%+v err=%v consensus=%+v", result, err, consensus.state)
		}
	})
}

func TestBootstrapRejectsSingleSideInitialCommitThatDoesNotMatchRecoveryRequest(t *testing.T) {
	_, committed, _ := startupCommittedState(t)
	machine, err := NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &InitialStateRequest{Version: committed.Desired.Version, Payload: []byte(`{"mode":"enforce"}`), Nonce: "nonce-1", Confirmation: InitialStateConfirmation{ID: "confirmation-recover-3", Actor: "admin", Reason: "recover initial commit"}}
	log := []string{}
	appended := 0
	durable := &startupDurableFake{log: &log, loadErr: ErrStateNotFound, append: func(Commit) { appended++ }}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: machine,
		Durable: durable, Consensus: &startupConsensusFake{state: committed, log: &log},
		Fencer: &startupFenceFake{log: &log}, InitialState: request,
		InitialAuthorizer: startupInitialAuthorizerFunc(func(context.Context, InitialStateRequest) error { return nil }),
	})
	if err == nil || !errors.Is(err, ErrStartupDiverged) || result.Ready || appended != 0 {
		t.Fatalf("mismatched single-side recovery accepted: result=%+v err=%v appended=%d", result, err, appended)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type startupInitialAuthorizerFunc func(context.Context, InitialStateRequest) error

func (f startupInitialAuthorizerFunc) AuthorizeInitialState(ctx context.Context, request InitialStateRequest) error {
	return f(ctx, request)
}

func TestBootstrapUsesLeadershipCheckpointForExistingPayload(t *testing.T) {
	local, previous, _ := startupCommittedState(t)
	newState := previous
	newState.Term = 2
	newState.Epoch = 2
	newState.LeaderID = "node-b"
	newState.WriteFrozen = false
	newState.FreezeReason = ""
	log := []string{}
	durable := &startupDurableFake{state: previous, log: &log}
	consensus := &startupConsensusFake{state: newState, log: &log}
	checkpoint := &startupCheckpointFake{state: newState, log: &log}
	fencer := &startupFenceFake{token: fenceForState(newState), log: &log}
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: local,
		Durable: durable, Consensus: consensus, Fencer: fencer,
		LeadershipCheckpoint: checkpoint,
	})
	if err != nil || !result.Ready {
		t.Fatalf("checkpoint bootstrap failed: result=%+v err=%v", result, err)
	}
	if checkpoint.calls != 1 || durable.checkpoints != 1 {
		t.Fatalf("checkpoint calls=%d durable checkpoints=%d, want one each", checkpoint.calls, durable.checkpoints)
	}
	if result.State.Term != 2 || result.State.Epoch != 2 || result.State.Desired.Digest != previous.Desired.Digest {
		t.Fatalf("checkpoint changed payload or metadata unexpectedly: %+v", result.State)
	}
}

func TestBootstrapRejectsLeadershipMetadataChangeWithoutCheckpoint(t *testing.T) {
	local, previous, _ := startupCommittedState(t)
	changed := previous
	changed.Term = 2
	changed.Epoch = 2
	changed.LeaderID = "node-b"
	result, err := Bootstrap(context.Background(), StartupOptions{
		Profile: StorageProfileProduction, ClusterID: "cluster-a", Machine: local,
		Durable:   &startupDurableFake{state: previous, log: new([]string)},
		Consensus: &startupConsensusFake{state: changed, log: new([]string)},
		Fencer:    &startupFenceFake{token: fenceForState(changed), log: new([]string)},
	})
	if err == nil || !errors.Is(err, ErrStartupDiverged) || result.Ready {
		t.Fatalf("uncheckpointed metadata change accepted: result=%+v err=%v", result, err)
	}
}

func fenceForState(state State) FenceToken {
	return FenceToken{ClusterID: state.ClusterID, LeaderID: state.LeaderID, Epoch: state.Epoch, Revision: state.Revision, Digest: state.Desired.Digest, Nonce: nonceForState(state)}
}

func nonceForState(state State) string {
	for nonce, revision := range state.NonceLedger {
		if revision == state.Revision {
			return nonce
		}
	}
	return ""
}

type startupCheckpointFake struct {
	state State
	log   *[]string
	calls int
}

func (f *startupCheckpointFake) CheckpointLeadership(_ context.Context, durable State, consensus State) (State, error) {
	f.calls++
	*f.log = append(*f.log, "leadership.checkpoint")
	if durable.Desired.Digest != consensus.Desired.Digest || durable.Revision != consensus.Revision {
		return State{}, ErrStartupDiverged
	}
	f.state = consensus
	return f.state, nil
}
