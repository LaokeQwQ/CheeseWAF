package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrInvalidCommit = errors.New("invalid control-plane commit")
)

type persistenceError struct {
	stage string
	err   error
}

func (e *persistenceError) Error() string {
	return fmt.Sprintf("%s persistence failed: %v", e.stage, e.err)
}
func (e *persistenceError) Unwrap() error { return e.err }

// Coordinator is the side-effect boundary between the deterministic state
// machine and the consensus/durable stores. It serializes one commit at a
// time, sends it to consensus before PostgreSQL, and remembers completed
// stages so a retry after a durable-store failure does not duplicate the
// consensus operation. Store implementations must remain idempotent because
// this in-memory stage ledger is intentionally lost on process restart.
type Coordinator struct {
	mu            sync.Mutex
	machine       *StateMachine
	consensus     ConsensusStore
	durable       DurableStore
	consensusDone map[commitKey]struct{}
	durableDone   map[commitKey]struct{}
}

// Initialize creates and persists the first desired-state commit for an
// established native-raft leader. It requires an explicit confirmation
// object, never invents a payload, and keeps the state machine frozen until a
// caller validates a current fence and invokes ResumeWrites.
func (c *Coordinator) Initialize(ctx context.Context, request InitialStateRequest) (Commit, error) {
	if c == nil {
		return Commit{}, ErrInvalidCommit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator initial-state context canceled")
		return Commit{}, err
	}
	current := c.machine.Snapshot()
	if err := validateInitialStateRequest(request, current.ClusterID); err != nil {
		c.machine.FreezeWrites("protected initial state is invalid")
		return Commit{}, fmt.Errorf("%w: %v", ErrStartupInitialState, err)
	}
	if current.Revision != 0 || current.LeaderID == "" || current.Term == 0 || current.Epoch == 0 {
		c.machine.FreezeWrites("initial state requires established leader")
		return Commit{}, fmt.Errorf("%w: initial state requires an established leader", ErrStartupInitialState)
	}
	// Build the commit from the already-established leadership snapshot. A
	// coordinator deliberately keeps its live machine frozen during startup;
	// constructing a fresh machine and calling InstallLeadership would reset
	// every non-zero leadership epoch back to one and create a stale fence.
	commit, err := NewInitialCommit(current.ClusterID, current, request)
	if err != nil {
		c.machine.FreezeWrites("initial desired state commit construction failed")
		return Commit{}, err
	}
	if err := c.consensus.Propose(ctx, commit); err != nil {
		c.machine.FreezeWrites("initial desired state consensus persistence failed")
		return Commit{}, &persistenceError{stage: "initial consensus", err: err}
	}
	if err := c.durable.AppendCommit(ctx, commit); err != nil {
		c.machine.FreezeWrites("initial desired state durable persistence failed")
		return Commit{}, &persistenceError{stage: "initial durable store", err: err}
	}
	if err := c.machine.LoadSnapshotIfCurrent(current, commit.State); err != nil {
		c.machine.FreezeWrites("initial state installation failed")
		return Commit{}, err
	}
	return commit, nil
}

// CheckpointLeadership is the constrained metadata-only transition used when
// a new native-raft term/epoch has the same desired payload as PostgreSQL. A
// durable adapter must explicitly implement DurableLeadershipCheckpointStore;
// the coordinator never overwrites its state through LoadSnapshot.
func (c *Coordinator) CheckpointLeadership(ctx context.Context, durable, consensus State) (State, error) {
	if c == nil {
		return State{}, ErrInvalidCommit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !startupPayloadEquivalent(durable, consensus) {
		return State{}, fmt.Errorf("%w: leadership checkpoint cannot alter desired payload", ErrStartupCheckpoint)
	}
	if err := validateLeadershipCheckpoint(durable, consensus); err != nil {
		return State{}, err
	}
	store, ok := c.durable.(DurableLeadershipCheckpointStore)
	if !ok {
		return State{}, fmt.Errorf("%w: durable store has no leadership checkpoint capability", ErrStartupCheckpoint)
	}
	if err := store.CheckpointLeadership(ctx, consensus); err != nil {
		return State{}, &persistenceError{stage: "leadership checkpoint", err: err}
	}
	updated, err := c.durable.LoadState(ctx, durable.ClusterID)
	if err != nil {
		return State{}, &persistenceError{stage: "leadership checkpoint verify", err: err}
	}
	if !startupStatesEquivalent(updated, consensus) {
		return State{}, fmt.Errorf("%w: durable leadership checkpoint did not converge", ErrStartupDiverged)
	}
	return updated, nil
}

type commitKey struct {
	clusterID string
	epoch     Epoch
	revision  Revision
	nonce     string
}

// NewCoordinator constructs a pure Go commit adapter. It does not connect to
// or probe either store.
func NewCoordinator(machine *StateMachine, consensus ConsensusStore, durable DurableStore) (*Coordinator, error) {
	if machine == nil || isNilStartupDependency(consensus) || isNilStartupDependency(durable) {
		return nil, fmt.Errorf("%w: machine, consensus and durable stores are required", ErrInvalidCommit)
	}
	return &Coordinator{
		machine:       machine,
		consensus:     consensus,
		durable:       durable,
		consensusDone: make(map[commitKey]struct{}),
		durableDone:   make(map[commitKey]struct{}),
	}, nil
}

// Apply persists a commit in the safety order: consensus first, then the
// durable store. A nil result means both stores acknowledged the exact same
// cluster/epoch/revision/digest/nonce tuple. If either store fails, Apply
// returns an error and never claims success; a later call may retry the
// incomplete stage.
func (c *Coordinator) Apply(ctx context.Context, commit Commit) error {
	if c == nil {
		return ErrInvalidCommit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled before apply")
		return err
	}
	// Keep stage transitions serialized. This prevents two callers from both
	// observing a missing stage and issuing duplicate side effects.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.machine.ValidateCommit(commit); err != nil {
		return err
	}
	key := commitKey{clusterID: commit.Fence.ClusterID, epoch: commit.Fence.Epoch, revision: commit.Fence.Revision, nonce: commit.Fence.Nonce}
	if _, done := c.durableDone[key]; done {
		return nil
	}
	current, err := c.durable.LoadState(ctx, key.clusterID)
	if errors.Is(err, ErrStateNotFound) {
		current = State{ClusterID: key.clusterID, WriteFrozen: true}
		err = nil
	}
	if err != nil {
		c.machine.FreezeWrites("durable baseline load failed")
		return &persistenceError{stage: "load durable baseline", err: err}
	}
	if current.Epoch == commit.Fence.Epoch && current.Revision > commit.Fence.Revision {
		c.machine.FreezeWrites("durable baseline is newer than commit")
		return ErrStaleRevision
	}
	if current.Epoch == commit.Fence.Epoch && current.Revision == commit.Fence.Revision && current.Revision != 0 {
		if !statesEquivalent(current, commit.State) {
			c.machine.FreezeWrites("durable baseline conflicts with commit")
			return ErrInvalidCommit
		}
		c.durableDone[key] = struct{}{}
		if err := c.machine.InstallCommit(commit); err != nil {
			c.machine.FreezeWrites("commit installation failed")
			return err
		}
		return nil
	}
	if _, done := c.consensusDone[key]; !done {
		if err := ctx.Err(); err != nil {
			c.machine.FreezeWrites("coordinator context canceled before consensus")
			return err
		}
		if err := c.consensus.Propose(ctx, commit); err != nil {
			c.machine.FreezeWrites("consensus persistence failed")
			return &persistenceError{stage: "consensus", err: err}
		}
		c.consensusDone[key] = struct{}{}
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled before durable store")
		return err
	}
	if err := c.durable.AppendCommit(ctx, commit); err != nil {
		c.machine.FreezeWrites("durable persistence failed")
		return &persistenceError{stage: "durable store", err: err}
	}
	c.durableDone[key] = struct{}{}
	if err := c.machine.InstallCommit(commit); err != nil {
		c.machine.FreezeWrites("commit installation failed")
		return err
	}
	return nil
}

// LoadSnapshot restores the state machine from the durable store. The next
// proposal then uses the restored epoch/revision as its CAS baseline.
func (c *Coordinator) LoadSnapshot(ctx context.Context) error {
	if c == nil {
		return ErrInvalidCommit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled before snapshot load")
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clusterID := c.machine.Snapshot().ClusterID
	consensusState, err := c.consensus.Current(ctx, clusterID)
	if err != nil {
		c.machine.FreezeWrites("consensus snapshot load failed")
		return &persistenceError{stage: "load consensus snapshot", err: err}
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled after consensus snapshot")
		return err
	}
	state, err := c.durable.LoadState(ctx, clusterID)
	if errors.Is(err, ErrStateNotFound) && isEmptyInitialState(consensusState) {
		return nil
	}
	if err != nil {
		c.machine.FreezeWrites("durable snapshot load failed")
		return &persistenceError{stage: "load snapshot", err: err}
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled after durable snapshot")
		return err
	}
	if !statesEquivalent(consensusState, state) {
		c.machine.FreezeWrites("consensus and durable snapshots diverged")
		return fmt.Errorf("%w: consensus and durable snapshots diverge", ErrInvalidCommit)
	}
	if err := c.machine.LoadSnapshot(state); err != nil {
		c.machine.FreezeWrites("snapshot installation failed")
		return err
	}
	c.consensusDone = make(map[commitKey]struct{})
	c.durableDone = make(map[commitKey]struct{})
	return nil
}

// ResumeWrites clears a fail-closed freeze only after consensus and durable
// snapshots still match the supplied current fencing token. The token binds
// the unfreeze to cluster, leader, epoch, revision, digest and nonce.
func (c *Coordinator) ResumeWrites(ctx context.Context, token FenceToken) error {
	if c == nil {
		return ErrInvalidCommit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled before resume")
		return err
	}
	if err := c.machine.ValidateFence(token); err != nil {
		c.machine.FreezeWrites("resume fencing token is stale")
		return err
	}
	clusterID := c.machine.Snapshot().ClusterID
	consensusState, err := c.consensus.Current(ctx, clusterID)
	if err != nil {
		c.machine.FreezeWrites("consensus resume check failed")
		return &persistenceError{stage: "resume consensus", err: err}
	}
	durableState, err := c.durable.LoadState(ctx, clusterID)
	if err != nil {
		c.machine.FreezeWrites("durable resume check failed")
		return &persistenceError{stage: "resume durable", err: err}
	}
	if !statesEquivalent(consensusState, durableState) || durableState.ClusterID != token.ClusterID || durableState.LeaderID != token.LeaderID || durableState.Term == 0 || durableState.Term != c.machine.Snapshot().Term || durableState.Epoch != token.Epoch || durableState.Revision != token.Revision || durableState.Desired.Digest != token.Digest || durableState.NonceLedger[token.Nonce] != token.Revision {
		c.machine.FreezeWrites("resume snapshots or fencing token diverged")
		return ErrInvalidCommit
	}
	if err := c.machine.ResumeWrites(token); err != nil {
		c.machine.FreezeWrites("resume authority rejected")
		return err
	}
	return nil
}

func isEmptyInitialState(state State) bool {
	return state.LeaderID == "" && state.Term == 0 && state.Epoch == 0 && state.Revision == 0 && state.WriteFrozen && len(state.Desired.Payload) == 0 && state.Desired.Version == "" && state.Desired.Digest == ""
}

func validateLeadershipCheckpoint(previous, next State) error {
	if previous.ClusterID == "" || next.ClusterID != previous.ClusterID || !startupPayloadEquivalent(previous, next) {
		return fmt.Errorf("%w: leadership checkpoint cluster or payload mismatch", ErrStartupCheckpoint)
	}
	if next.Revision != previous.Revision || next.Epoch < previous.Epoch || (next.Epoch == previous.Epoch && next.Term < previous.Term) {
		return fmt.Errorf("%w: leadership checkpoint regresses state", ErrStartupCheckpoint)
	}
	if next.Epoch == previous.Epoch && (next.Term != previous.Term || next.LeaderID != previous.LeaderID) {
		return fmt.Errorf("%w: leadership change within an epoch is invalid", ErrStartupCheckpoint)
	}
	if next.Epoch > previous.Epoch && next.Term <= previous.Term {
		return fmt.Errorf("%w: epoch advance requires higher term", ErrStartupCheckpoint)
	}
	if next.LeaderID == "" || next.Term == 0 || next.Epoch == 0 || next.WriteFrozen {
		return fmt.Errorf("%w: checkpoint requires an active leader", ErrStartupCheckpoint)
	}
	return nil
}

func statesEquivalent(a, b State) bool {
	if a.ClusterID != b.ClusterID || a.LeaderID != b.LeaderID || a.Term != b.Term || a.Epoch != b.Epoch || a.Revision != b.Revision || a.Desired.Version != b.Desired.Version || a.Desired.Digest != b.Desired.Digest || string(a.Desired.Payload) != string(b.Desired.Payload) || a.WriteFrozen != b.WriteFrozen || a.FreezeReason != b.FreezeReason {
		return false
	}
	if len(a.NonceLedger) != len(b.NonceLedger) {
		return false
	}
	for nonce, revision := range a.NonceLedger {
		if b.NonceLedger[nonce] != revision {
			return false
		}
	}
	return true
}
