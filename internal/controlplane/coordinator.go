package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
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
	mu             sync.Mutex
	machine        *StateMachine
	consensus      ConsensusStore
	durable        DurableStore
	consensusTried map[commitKey]Commit
	consensusDone  map[commitKey]Commit
	durableDone    map[commitKey]Commit
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
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	current := c.machine.Snapshot()
	if err := validateInitialStateRequest(request, current.ClusterID); err != nil {
		c.machine.FreezeWrites("protected initial state is invalid")
		return Commit{}, fmt.Errorf("%w: %v", ErrStartupInitialState, err)
	}
	key := commitKey{clusterID: current.ClusterID, epoch: current.Epoch, revision: 1, nonce: request.Nonce}
	commit, retry := c.initialRetryCommit(key)
	if retry {
		if !commitMatchesCurrentGeneration(current, commit) {
			return Commit{}, ErrStaleEpoch
		}
		if !initialRequestMatchesCommit(request, commit) {
			c.machine.FreezeWrites("initial retry conflicts with exact commit")
			return Commit{}, ErrInvalidCommit
		}
	} else {
		if current.Revision != 0 || current.LeaderID == "" || current.Term == 0 || current.Epoch == 0 {
			c.machine.FreezeWrites("initial state requires established leader")
			return Commit{}, fmt.Errorf("%w: initial state requires an established leader", ErrStartupInitialState)
		}
		// Build the commit from the already-established leadership snapshot. A
		// coordinator deliberately keeps its live machine frozen during startup;
		// constructing a fresh machine and calling InstallLeadership would reset
		// every non-zero leadership epoch back to one and create a stale fence.
		var err error
		commit, err = NewInitialCommit(current.ClusterID, current, request)
		if err != nil {
			c.machine.FreezeWrites("initial desired state commit construction failed")
			return Commit{}, err
		}
	}
	return c.applyInitialLocked(ctx, current, key, commit)
}

func (c *Coordinator) initialRetryCommit(key commitKey) (Commit, bool) {
	if commit, ok := c.durableDone[key]; ok {
		return cloneCommit(commit), true
	}
	if commit, ok := c.consensusDone[key]; ok {
		return cloneCommit(commit), true
	}
	if commit, ok := c.consensusTried[key]; ok {
		return cloneCommit(commit), true
	}
	return Commit{}, false
}

func initialRequestMatchesCommit(request InitialStateRequest, commit Commit) bool {
	digest := request.Digest
	if digest == "" {
		digest = Digest(request.Payload)
	}
	return commit.State.Revision == 1 && commit.State.Desired.Version == request.Version && commit.State.Desired.Digest == digest &&
		string(commit.State.Desired.Payload) == string(request.Payload) && commit.Fence.Nonce == request.Nonce && commit.State.NonceLedger[request.Nonce] == 1
}

func (c *Coordinator) applyInitialLocked(ctx context.Context, current State, key commitKey, commit Commit) (Commit, error) {
	if completed, ok := c.durableDone[key]; ok {
		if !commitsEquivalent(completed, commit) {
			c.machine.FreezeWrites("initial durable completion conflicts with commit")
			return commit, ErrInvalidCommit
		}
		return commit, nil
	}
	consensusCommit, consensusDone := c.consensusDone[key]
	if consensusDone && !commitsEquivalent(consensusCommit, commit) {
		c.machine.FreezeWrites("initial consensus completion conflicts with commit")
		return commit, ErrInvalidCommit
	}
	if err := ctx.Err(); err != nil {
		return commit, err
	}
	if !consensusDone {
		c.consensusTried[key] = cloneCommit(commit)
		if err := c.consensus.Propose(ctx, commit); err != nil {
			c.machine.FreezeWrites("initial desired state consensus persistence failed")
			return commit, &persistenceError{stage: "initial consensus", err: err}
		}
		c.consensusDone[key] = cloneCommit(commit)
		delete(c.consensusTried, key)
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled before initial durable store")
		return commit, err
	}
	if err := c.durable.AppendCommit(ctx, commit); err != nil {
		c.machine.FreezeWrites("initial desired state durable persistence failed")
		return commit, &persistenceError{stage: "initial durable store", err: err}
	}
	if !localStateCarriesCommit(c.machine.Snapshot(), commit) {
		if err := c.machine.LoadSnapshotIfCurrent(current, commit.State); err != nil {
			c.machine.FreezeWrites("initial state installation failed")
			return commit, err
		}
	}
	c.durableDone[key] = cloneCommit(commit)
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
		machine:        machine,
		consensus:      consensus,
		durable:        durable,
		consensusTried: make(map[commitKey]Commit),
		consensusDone:  make(map[commitKey]Commit),
		durableDone:    make(map[commitKey]Commit),
	}, nil
}

// ProposeAndApply owns the complete proposal lifecycle under the coordinator
// lock. Callers provide the CAS baseline and immutable payload, but never
// mutate the state machine separately before persistence. If persistence
// fails, the returned Commit is still the exact proposal to retry with Apply;
// the state machine remains fail-closed until that retry succeeds and a
// current fence is explicitly resumed.
func (c *Coordinator) ProposeAndApply(ctx context.Context, proposal Proposal) (Commit, error) {
	if c == nil {
		return Commit{}, ErrInvalidCommit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Commit{}, err
	}
	commit, err := c.machine.Propose(proposal)
	if err != nil {
		return Commit{}, err
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled after proposal")
		return commit, err
	}
	if err := c.applyLocked(ctx, commit, true); err != nil {
		return commit, err
	}
	return commit, nil
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
		return err
	}
	// Keep stage transitions serialized. This prevents two callers from both
	// observing a missing stage and issuing duplicate side effects.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyLocked(ctx, commit, false)
}

func (c *Coordinator) applyLocked(ctx context.Context, commit Commit, proposalOwned bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := commitKey{clusterID: commit.Fence.ClusterID, epoch: commit.Fence.Epoch, revision: commit.Fence.Revision, nonce: commit.Fence.Nonce}
	if completed, done := c.durableDone[key]; done {
		if !commitMatchesCurrentGeneration(c.machine.Snapshot(), commit) {
			return ErrStaleEpoch
		}
		if !commitsEquivalent(completed, commit) {
			c.machine.FreezeWrites("durable completion key conflicts with commit")
			return ErrInvalidCommit
		}
		return nil
	}
	consensusCommit, consensusDone := c.consensusDone[key]
	attemptedCommit, consensusTried := c.consensusTried[key]
	if consensusDone {
		if !commitMatchesCurrentGeneration(c.machine.Snapshot(), commit) {
			return ErrStaleEpoch
		}
		if !commitsEquivalent(consensusCommit, commit) {
			c.machine.FreezeWrites("consensus completion key conflicts with commit")
			return ErrInvalidCommit
		}
	} else if consensusTried {
		if !commitMatchesCurrentGeneration(c.machine.Snapshot(), commit) {
			return ErrStaleEpoch
		}
		if !commitsEquivalent(attemptedCommit, commit) {
			c.machine.FreezeWrites("consensus attempt key conflicts with commit")
			return ErrInvalidCommit
		}
	} else if err := c.machine.ValidateCommit(commit); err != nil {
		return err
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
	if current.Epoch > commit.Fence.Epoch {
		c.machine.FreezeWrites("durable baseline has a newer epoch")
		return ErrStaleEpoch
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
		if !consensusDone {
			consensusState, consensusErr := c.consensus.Current(ctx, key.clusterID)
			if consensusErr != nil {
				c.machine.FreezeWrites("consensus completion verification failed")
				return &persistenceError{stage: "verify consensus completion", err: consensusErr}
			}
			if !replicatedStateCarriesCommit(consensusState, commit) {
				c.machine.FreezeWrites("durable commit is not present in consensus")
				return ErrInvalidCommit
			}
		}
		if err := c.installCommitIfNeeded(commit); err != nil {
			c.machine.FreezeWrites("commit installation failed")
			return err
		}
		c.durableDone[key] = cloneCommit(commit)
		return nil
	}
	if !consensusDone {
		if err := ctx.Err(); err != nil {
			if proposalOwned {
				c.machine.FreezeWrites("coordinator context canceled before consensus")
			}
			return err
		}
		c.consensusTried[key] = cloneCommit(commit)
		if err := c.consensus.Propose(ctx, commit); err != nil {
			c.machine.FreezeWrites("consensus persistence failed")
			return &persistenceError{stage: "consensus", err: err}
		}
		c.consensusDone[key] = cloneCommit(commit)
		delete(c.consensusTried, key)
	}
	if err := ctx.Err(); err != nil {
		c.machine.FreezeWrites("coordinator context canceled before durable store")
		return err
	}
	if err := c.durable.AppendCommit(ctx, commit); err != nil {
		c.machine.FreezeWrites("durable persistence failed")
		return &persistenceError{stage: "durable store", err: err}
	}
	if err := c.installCommitIfNeeded(commit); err != nil {
		c.machine.FreezeWrites("commit installation failed")
		return err
	}
	c.durableDone[key] = cloneCommit(commit)
	return nil
}

func (c *Coordinator) installCommitIfNeeded(commit Commit) error {
	if localStateCarriesCommit(c.machine.Snapshot(), commit) {
		return nil
	}
	return c.machine.InstallCommit(commit)
}

// localStateCarriesCommit ignores only the process-local freeze overlay. It is
// used after the exact commit has already been established by the coordinator
// stage ledger or a strict durable/consensus comparison.
func localStateCarriesCommit(state State, commit Commit) bool {
	return stateCarriesExactCommit(state, commit)
}

func replicatedStateCarriesCommit(state State, commit Commit) bool {
	return statesEquivalent(state, commit.State) && commit.Fence.ClusterID == state.ClusterID && commit.Fence.LeaderID == state.LeaderID &&
		commit.Fence.Epoch == state.Epoch && commit.Fence.Revision == state.Revision && commit.Fence.Digest == state.Desired.Digest &&
		state.NonceLedger[commit.Fence.Nonce] == state.Revision
}

func commitMatchesCurrentGeneration(current State, commit Commit) bool {
	return current.ClusterID == commit.Fence.ClusterID && current.LeaderID == commit.Fence.LeaderID && current.Term == commit.State.Term && current.Epoch == commit.Fence.Epoch
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
	c.consensusDone = make(map[commitKey]Commit)
	c.consensusTried = make(map[commitKey]Commit)
	c.durableDone = make(map[commitKey]Commit)
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
	if a.ClusterID != b.ClusterID || a.LeaderID != b.LeaderID || a.Term != b.Term || a.Epoch != b.Epoch || a.Revision != b.Revision || a.Desired.Version != b.Desired.Version || a.Desired.Digest != b.Desired.Digest || string(a.Desired.Payload) != string(b.Desired.Payload) || a.WriteFrozen != b.WriteFrozen || a.FreezeReason != b.FreezeReason || !durableTimestampsEquivalent(a.UpdatedAt, b.UpdatedAt) {
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

// durableTimestampsEquivalent compares metadata at PostgreSQL TIMESTAMPTZ
// precision. Consensus retains Go nanoseconds, while the PostgreSQL round trip
// truncates them to microseconds. Commit-history idempotency still
// compares the original state_json exactly; only the cross-store snapshot
// convergence check uses this canonical durable precision.
func durableTimestampsEquivalent(a, b time.Time) bool {
	return a.UTC().Truncate(time.Microsecond).Equal(b.UTC().Truncate(time.Microsecond))
}
