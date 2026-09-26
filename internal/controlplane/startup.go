package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Startup stages make the production control-plane boot contract observable
// without exposing backend implementation details. A caller must not start
// management writes or advertise readiness before StartupStageReady.
type StartupStage string

const (
	StartupStageContract  StartupStage = "contract"
	StartupStageDurable   StartupStage = "durable"
	StartupStageConsensus StartupStage = "consensus"
	StartupStageSnapshot  StartupStage = "snapshot"
	StartupStageFencing   StartupStage = "fencing"
	StartupStageReady     StartupStage = "ready"
	StartupStageFailed    StartupStage = "failed"
)

const (
	StorageProfileTemporary    = "temporary"
	StorageProfileProduction   = "production"
	DurableBackendPostgreSQL   = "postgresql"
	ConsensusBackendNativeRaft = "native-raft"
)

var (
	ErrStartupContract     = errors.New("invalid production control-plane startup contract")
	ErrStartupDurable      = errors.New("production durable state startup failed")
	ErrStartupConsensus    = errors.New("native-raft consensus startup failed")
	ErrStartupDiverged     = errors.New("durable and consensus snapshots diverged")
	ErrStartupFencing      = errors.New("production fencing could not be established")
	ErrStartupInitialState = errors.New("protected initial control-plane state is required")
	ErrStartupCheckpoint   = errors.New("leadership checkpoint is required for metadata changes")
)

// InitialStateRequest is a one-shot, administrator-authorized import for a
// cluster whose durable and consensus stores contain no desired payload.
// Empty snapshots never invent a payload or nonce.
type InitialStateRequest struct {
	Version      string                   `json:"version"`
	Payload      json.RawMessage          `json:"payload"`
	Digest       string                   `json:"digest,omitempty"`
	Nonce        string                   `json:"nonce"`
	Confirmation InitialStateConfirmation `json:"confirmation"`
}

// InitialStateConfirmation records the explicit administrator acknowledgement
// required before the first desired-state commit. It is metadata only; an
// outer approval service may additionally verify the actor.
type InitialStateConfirmation struct {
	ID     string `json:"id"`
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

// InitialStateAuthorizer is an optional external approval boundary. When
// present, Bootstrap invokes it after local confirmation fields validate and
// before producing the first commit.
type InitialStateAuthorizer interface {
	AuthorizeInitialState(context.Context, InitialStateRequest) error
}

// LeadershipCheckpointStore is the constrained boundary used when PG and
// native-raft hold the same desired payload but different leadership
// metadata. Implementations must atomically validate and persist the metadata
// transition; Bootstrap never overwrites the older state directly.
type LeadershipCheckpointStore interface {
	CheckpointLeadership(context.Context, State, State) (State, error)
}

// DurableLeadershipCheckpointStore persists a leadership-only metadata
// transition while retaining the exact desired payload and revision. It is a
// separate optional capability so existing DurableStore implementations keep
// compiling; when absent, a metadata mismatch is rejected fail-closed.
type DurableLeadershipCheckpointStore interface {
	CheckpointLeadership(context.Context, State) error
}

// DurableBootstrap is the production durable-state boundary. A PostgreSQL
// adapter should perform migrations in Prepare and a connectivity/readiness
// probe in Health before LoadState is called.
type DurableBootstrap interface {
	DurableStore
	Backend() string
	Prepare(context.Context) error
	Health(context.Context) error
}

// ConsensusBootstrap is the native-raft/coordinator boundary. Prepare must
// start or attach the coordinator; Health must verify that its term/member
// view is usable before Current is read.
type ConsensusBootstrap interface {
	ConsensusStore
	Backend() string
	Prepare(context.Context) error
	Health(context.Context) error
}

// ConsensusCommitRecoveryStore exposes the exact latest desired-state commit
// retained by consensus. Bootstrap uses it only when consensus is exactly one
// revision ahead of durable storage, which is the bounded crash window left
// by the coordinator's consensus-before-PostgreSQL ordering.
type ConsensusCommitRecoveryStore interface {
	CurrentCommit(context.Context, string) (Commit, error)
}

// FenceBootstrap establishes the current leader/epoch fencing token after the
// two durable snapshots have been compared. Implementations must prove that
// the returned token is active for the supplied state; they must not fabricate
// a new leader or epoch during this step.
type FenceBootstrap interface {
	Establish(context.Context, State) (FenceToken, error)
}

// StartupOptions contains only production control-plane dependencies. The
// complete management storage adapter is intentionally not represented as a
// storage.Store: it has a different contract and must be opened by the outer
// serve layer before it calls this helper.
type StartupOptions struct {
	Profile              string
	ClusterID            string
	Machine              *StateMachine
	Durable              DurableBootstrap
	Consensus            ConsensusBootstrap
	Fencer               FenceBootstrap
	InitialState         *InitialStateRequest
	InitialAuthorizer    InitialStateAuthorizer
	LeadershipCheckpoint LeadershipCheckpointStore
}

// StartupResult is a read-only readiness snapshot. LastKnownGood is always
// taken from the state machine's committed state; a failed startup never
// exposes an uncommitted proposal.
type StartupResult struct {
	Stage         StartupStage
	Ready         bool
	State         State
	LastKnownGood State
	Fence         FenceToken
	Coordinator   *Coordinator
}

// ValidateStartupOptions checks the production-only backend boundary without
// performing network or database work.
func ValidateStartupOptions(opts StartupOptions) error {
	if strings.ToLower(strings.TrimSpace(opts.Profile)) != StorageProfileProduction {
		return fmt.Errorf("%w: storage profile %q is not production; temporary SQLite must use its existing path", ErrStartupContract, opts.Profile)
	}
	if !validStartupIdentifier(opts.ClusterID) || opts.Machine == nil || isNilStartupDependency(opts.Durable) || isNilStartupDependency(opts.Consensus) || isNilStartupDependency(opts.Fencer) {
		return fmt.Errorf("%w: cluster id, state machine, durable bootstrap, consensus bootstrap and fencer are required", ErrStartupContract)
	}
	if opts.Machine.Snapshot().ClusterID != opts.ClusterID {
		return fmt.Errorf("%w: state machine cluster id does not match startup cluster id", ErrStartupContract)
	}
	if opts.Durable.Backend() != DurableBackendPostgreSQL || opts.Consensus.Backend() != ConsensusBackendNativeRaft {
		return fmt.Errorf("%w: durable backend must be postgresql and consensus backend must be native-raft; SQLite, builtin and etcd are compatibility backends", ErrStartupContract)
	}
	if opts.InitialState != nil {
		if err := validateInitialStateRequest(*opts.InitialState, opts.ClusterID); err != nil {
			return fmt.Errorf("%w: %v", ErrStartupInitialState, err)
		}
		if opts.InitialAuthorizer == nil {
			return fmt.Errorf("%w: protected initial state requires an external administrator authorizer", ErrStartupInitialState)
		}
	}
	if opts.InitialAuthorizer != nil && isNilStartupDependency(opts.InitialAuthorizer) {
		return fmt.Errorf("%w: initial state authorizer is nil", ErrStartupContract)
	}
	if opts.LeadershipCheckpoint != nil && isNilStartupDependency(opts.LeadershipCheckpoint) {
		return fmt.Errorf("%w: leadership checkpoint is nil", ErrStartupContract)
	}
	return nil
}

// Bootstrap performs the fail-closed production startup sequence:
//
//  1. prepare and health-check PostgreSQL durable state;
//  2. load the durable snapshot;
//  3. prepare and health-check native-raft/coordinator;
//  4. load and compare its snapshot;
//  5. install the equal snapshot and establish its fencing token;
//  6. report ready.
//
// It is a control-plane contract only. The existing serve path must still
// provide a complete management storage.Store before exposing management APIs.
func Bootstrap(ctx context.Context, opts StartupOptions) (StartupResult, error) {
	result := StartupResult{Stage: StartupStageContract}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ValidateStartupOptions(opts); err != nil {
		if strings.EqualFold(strings.TrimSpace(opts.Profile), StorageProfileProduction) && opts.Machine != nil {
			failed := FailClosed(opts.Machine, "control-plane startup contract rejected")
			failed.Stage = StartupStageContract
			return failed, err
		}
		return result, err
	}
	clusterID := opts.ClusterID
	if err := ctx.Err(); err != nil {
		failed := FailClosed(opts.Machine, "control-plane startup context canceled")
		failed.Stage = StartupStageContract
		return failed, fmt.Errorf("%w: %w", ErrStartupContract, err)
	}
	previous := opts.Machine.Snapshot()
	opts.Machine.FreezeWrites("control-plane startup incomplete")
	installBaseline := opts.Machine.Snapshot()

	fail := func(stage StartupStage, sentinel error, reason string, err error) (StartupResult, error) {
		op := opts.Machine.Snapshot()
		op.WriteFrozen = true
		op.FreezeReason = strings.TrimSpace(reason)
		if err != nil {
			op.FreezeReason = fmt.Sprintf("%s: %v", op.FreezeReason, err)
		}
		opResult := FailClosed(opts.Machine, op.FreezeReason)
		opResult.Stage = stage
		if sentinel == nil {
			return opResult, err
		}
		if err == nil {
			err = errors.New(reason)
		}
		return opResult, fmt.Errorf("%w: %w", sentinel, err)
	}

	result.Stage = StartupStageDurable
	if err := opts.Durable.Prepare(ctx); err != nil {
		return fail(StartupStageDurable, ErrStartupDurable, "durable prepare failed", err)
	}
	if err := opts.Durable.Health(ctx); err != nil {
		return fail(StartupStageDurable, ErrStartupDurable, "durable health check failed", err)
	}
	if err := ctx.Err(); err != nil {
		return fail(StartupStageDurable, ErrStartupDurable, "startup context canceled before durable snapshot", err)
	}
	durableState, err := opts.Durable.LoadState(ctx, clusterID)
	durableMissing := errors.Is(err, ErrStateNotFound)
	if errors.Is(err, ErrStateNotFound) {
		durableState = emptyStartupState(clusterID)
		err = nil
	}
	if err != nil {
		return fail(StartupStageDurable, ErrStartupDurable, "durable snapshot load failed", err)
	}
	if durableState.ClusterID != clusterID {
		return fail(StartupStageSnapshot, ErrStartupDiverged, "durable snapshot cluster binding mismatch", nil)
	}
	if err := ctx.Err(); err != nil {
		return fail(StartupStageDurable, ErrStartupDurable, "startup context canceled after durable state", err)
	}

	result.Stage = StartupStageConsensus
	if err := opts.Consensus.Prepare(ctx); err != nil {
		return fail(StartupStageConsensus, ErrStartupConsensus, "consensus prepare failed", err)
	}
	if err := opts.Consensus.Health(ctx); err != nil {
		return fail(StartupStageConsensus, ErrStartupConsensus, "consensus health check failed", err)
	}
	// Native-raft may replay its log and install a new leadership term while
	// Prepare/Health waits for readiness. Anchor the installation CAS after that
	// recovery, while keeping writes frozen until the durable snapshot and
	// current fence have both been verified. A later leadership change still
	// invalidates this baseline and fails the final CAS.
	opts.Machine.FreezeWrites("control-plane startup incomplete")
	installBaseline = opts.Machine.Snapshot()
	if err := ctx.Err(); err != nil {
		return fail(StartupStageConsensus, ErrStartupConsensus, "startup context canceled before consensus snapshot", err)
	}
	consensusState, err := opts.Consensus.Current(ctx, clusterID)
	consensusMissing := errors.Is(err, ErrStateNotFound)
	if errors.Is(err, ErrStateNotFound) {
		consensusState = emptyStartupState(clusterID)
		err = nil
	}
	if err != nil {
		return fail(StartupStageConsensus, ErrStartupConsensus, "consensus snapshot load failed", err)
	}
	if consensusState.ClusterID != clusterID {
		return fail(StartupStageSnapshot, ErrStartupDiverged, "consensus snapshot cluster binding mismatch", nil)
	}
	// A crash during the first protected commit can leave exactly one backend
	// at revision 1. Recovery is permitted only when the surviving commit is the
	// exact administrator-authorized InitialState. Arbitrary divergence, later
	// revisions, or a different nonce/payload remain fail-closed.
	if opts.InitialState != nil {
		request := *opts.InitialState
		if request.Digest == "" {
			request.Digest = Digest(request.Payload)
		}
		durableInitial := startupInitialStateMatches(durableState, request)
		consensusInitial := startupInitialStateMatches(consensusState, request)
		switch {
		case consensusInitial && startupPayloadEmpty(durableState):
			if !durableMissing && !isEmptyInitialState(durableState) {
				return fail(StartupStageSnapshot, ErrStartupDiverged, "empty durable recovery baseline is invalid", nil)
			}
			if opts.InitialAuthorizer == nil {
				return fail(StartupStageSnapshot, ErrStartupInitialState, "single-side initial-state recovery requires an external administrator authorizer", nil)
			}
			if err := authorizeInitialState(ctx, opts.InitialAuthorizer, request); err != nil {
				return fail(StartupStageSnapshot, ErrStartupInitialState, "administrator did not authorize initial-state recovery", err)
			}
			commit, recoveryErr := exactInitialConsensusCommit(ctx, opts.Consensus, clusterID, request, consensusState)
			if recoveryErr != nil {
				return fail(StartupStageSnapshot, ErrStartupDiverged, "consensus initial commit recovery is not exact", recoveryErr)
			}
			if recoveryErr = opts.Durable.AppendCommit(ctx, commit); recoveryErr != nil {
				return fail(StartupStageDurable, ErrStartupDurable, "initial desired state durable recovery failed", recoveryErr)
			}
			// Preserve the original Raft commit verbatim. If leadership changed
			// after that commit, the normal divergence path below persists the
			// newer leadership metadata as a separate checkpoint.
			durableState = commit.State
		case durableInitial && startupPayloadEmpty(consensusState):
			if consensusMissing || consensusState.LeaderID == "" || consensusState.Term == 0 || consensusState.Epoch == 0 || consensusState.WriteFrozen {
				return fail(StartupStageSnapshot, ErrStartupDiverged, "consensus recovery requires an active leader-only baseline", nil)
			}
			if opts.InitialAuthorizer == nil {
				return fail(StartupStageSnapshot, ErrStartupInitialState, "single-side initial-state recovery requires an external administrator authorizer", nil)
			}
			if err := authorizeInitialState(ctx, opts.InitialAuthorizer, request); err != nil {
				return fail(StartupStageSnapshot, ErrStartupInitialState, "administrator did not authorize initial-state recovery", err)
			}
			commit, createErr := startupCommitForLeadership(clusterID, consensusState, request)
			if createErr != nil {
				return fail(StartupStageSnapshot, ErrStartupInitialState, "initial desired state recovery proposal failed", createErr)
			}
			if createErr = opts.Consensus.Propose(ctx, commit); createErr != nil {
				return fail(StartupStageConsensus, ErrStartupConsensus, "initial desired state consensus recovery failed", createErr)
			}
			consensusState = commit.State
		}
	}
	// A coordinator freezes further proposals after consensus succeeds and the
	// durable append fails, so a valid crash-recovery gap is exactly one
	// revision. Revision zero to one remains protected by the explicit initial
	// state authorization path above and is never recovered implicitly.
	if durableState.Revision > 0 && consensusState.Revision == durableState.Revision+1 {
		recovery, ok := opts.Consensus.(ConsensusCommitRecoveryStore)
		if !ok || isNilStartupDependency(recovery) {
			return fail(StartupStageSnapshot, ErrStartupDiverged, "consensus is ahead but cannot provide the exact commit", nil)
		}
		commit, recoveryErr := recovery.CurrentCommit(ctx, clusterID)
		if recoveryErr != nil {
			return fail(StartupStageSnapshot, ErrStartupDiverged, "consensus-ahead exact commit lookup failed", recoveryErr)
		}
		if recoveryErr = validateConsensusAheadRecovery(durableState, consensusState, commit); recoveryErr != nil {
			return fail(StartupStageSnapshot, ErrStartupDiverged, "consensus-ahead exact commit validation failed", recoveryErr)
		}
		if recoveryErr = opts.Durable.AppendCommit(ctx, commit); recoveryErr != nil {
			return fail(StartupStageDurable, ErrStartupDurable, "consensus-ahead durable recovery failed", recoveryErr)
		}
		durableState = commit.State
	}
	if startupPayloadEmpty(durableState) && startupPayloadEmpty(consensusState) {
		if opts.InitialState == nil {
			return fail(StartupStageFencing, errors.Join(ErrStartupFencing, ErrStartupInitialState), "both durable and consensus snapshots are empty; protected initial state and administrator confirmation are required", nil)
		}
		if durableMissing == false && !isEmptyInitialState(durableState) {
			return fail(StartupStageSnapshot, ErrStartupInitialState, "initial state import is only valid for an empty durable snapshot", nil)
		}
		if consensusMissing == false && !isEmptyInitialState(consensusState) && consensusState.Revision != 0 {
			return fail(StartupStageSnapshot, ErrStartupInitialState, "initial state import is only valid for an empty consensus snapshot", nil)
		}
		if consensusState.LeaderID == "" || consensusState.Term == 0 || consensusState.Epoch == 0 || consensusState.WriteFrozen {
			return fail(StartupStageSnapshot, ErrStartupInitialState, "initial state requires an established native-raft leader checkpoint", nil)
		}
		if err := authorizeInitialState(ctx, opts.InitialAuthorizer, *opts.InitialState); err != nil {
			return fail(StartupStageSnapshot, ErrStartupInitialState, "administrator did not authorize initial state", err)
		}
		request := *opts.InitialState
		commit, createErr := startupCommitForLeadership(clusterID, consensusState, request)
		if createErr != nil {
			return fail(StartupStageSnapshot, ErrStartupInitialState, "initial desired state proposal failed", createErr)
		}
		if createErr = opts.Consensus.Propose(ctx, commit); createErr != nil {
			return fail(StartupStageConsensus, ErrStartupConsensus, "initial desired state consensus persistence failed", createErr)
		}
		if createErr = opts.Durable.AppendCommit(ctx, commit); createErr != nil {
			return fail(StartupStageDurable, ErrStartupDurable, "initial desired state durable persistence failed", createErr)
		}
		durableState, consensusState = commit.State, commit.State
	} else if !startupStatesEquivalent(durableState, consensusState) {
		if startupPayloadEquivalent(durableState, consensusState) && opts.LeadershipCheckpoint != nil {
			checkpoint, checkpointErr := opts.LeadershipCheckpoint.CheckpointLeadership(ctx, durableState, consensusState)
			if checkpointErr != nil {
				return fail(StartupStageSnapshot, ErrStartupDiverged, "leadership checkpoint failed", checkpointErr)
			}
			if checkpointErr = validateLeadershipCheckpoint(durableState, checkpoint); checkpointErr != nil {
				return fail(StartupStageSnapshot, ErrStartupDiverged, "leadership checkpoint validation failed", checkpointErr)
			}
			if !startupPayloadEquivalent(durableState, checkpoint) || !startupLeadershipEquivalent(checkpoint, consensusState) {
				return fail(StartupStageSnapshot, ErrStartupDiverged, "leadership checkpoint changed desired payload or leadership unexpectedly", nil)
			}
			if store, ok := opts.Durable.(DurableLeadershipCheckpointStore); ok {
				if checkpointErr = store.CheckpointLeadership(ctx, checkpoint); checkpointErr != nil {
					return fail(StartupStageDurable, ErrStartupDurable, "durable leadership checkpoint failed", checkpointErr)
				}
			} else {
				return fail(StartupStageSnapshot, errors.Join(ErrStartupDiverged, ErrStartupCheckpoint), "durable store cannot persist leadership checkpoint", nil)
			}
			durableState, consensusState = checkpoint, checkpoint
		} else {
			return fail(StartupStageSnapshot, ErrStartupDiverged, "durable and consensus snapshots differ", nil)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(StartupStageConsensus, ErrStartupConsensus, "startup context canceled after consensus state", err)
	}
	if startupSnapshotRegresses(previous, durableState) || startupSnapshotRegresses(installBaseline, durableState) {
		return fail(StartupStageSnapshot, ErrStartupDiverged, "startup snapshot regresses the local last-known-good state", nil)
	}
	candidate, err := NewStateMachine(clusterID, nil)
	if err != nil {
		return fail(StartupStageSnapshot, ErrStartupDiverged, "candidate state machine creation failed", err)
	}
	if err := candidate.LoadSnapshot(durableState); err != nil {
		return fail(StartupStageSnapshot, ErrStartupDiverged, "snapshot validation failed", err)
	}
	if err := ctx.Err(); err != nil {
		return fail(StartupStageFencing, ErrStartupFencing, "startup context canceled before fencing", err)
	}

	result.Stage = StartupStageFencing
	fence, err := opts.Fencer.Establish(ctx, durableState)
	if err != nil {
		return fail(StartupStageFencing, ErrStartupFencing, "fencing establishment failed", err)
	}
	if err := validateStartupFence(durableState, fence); err != nil {
		return fail(StartupStageFencing, ErrStartupFencing, "fencing token does not bind to snapshot", err)
	}
	if err := ctx.Err(); err != nil {
		return fail(StartupStageFencing, ErrStartupFencing, "startup context canceled after fencing", err)
	}
	latest, err := opts.Consensus.Current(ctx, clusterID)
	if err != nil {
		return fail(StartupStageFencing, ErrStartupFencing, "consensus changed check failed", err)
	}
	if latest.ClusterID != durableState.ClusterID || latest.Term != durableState.Term || latest.LeaderID != durableState.LeaderID || latest.Epoch != durableState.Epoch || latest.Revision != durableState.Revision || latest.Desired.Digest != durableState.Desired.Digest || !startupStatesEquivalent(latest, durableState) {
		return fail(StartupStageFencing, ErrStartupFencing, "leader or epoch changed after fencing", nil)
	}
	if err := opts.Machine.LoadSnapshotIfCurrent(installBaseline, durableState); err != nil {
		return fail(StartupStageSnapshot, ErrStartupDiverged, "snapshot installation failed", err)
	}
	if err := opts.Machine.ResumeWrites(fence); err != nil {
		return fail(StartupStageFencing, ErrStartupFencing, "startup resume authority failed", err)
	}
	coordinator, err := NewCoordinator(opts.Machine, opts.Consensus, opts.Durable)
	if err != nil {
		return fail(StartupStageConsensus, ErrStartupConsensus, "coordinator construction failed", err)
	}
	result = StartupResult{
		Stage:         StartupStageReady,
		Ready:         true,
		State:         opts.Machine.Snapshot(),
		LastKnownGood: opts.Machine.Snapshot(),
		Fence:         fence,
		Coordinator:   coordinator,
	}
	return result, nil
}

// FailClosed freezes new control-plane writes while preserving the committed
// desired state for data-plane last-known-good serving. It is safe to call on
// health transitions after a successful bootstrap.
func FailClosed(machine *StateMachine, reason string) StartupResult {
	if machine == nil {
		return StartupResult{Stage: StartupStageFailed, State: State{WriteFrozen: true, FreezeReason: "state machine unavailable"}, LastKnownGood: State{WriteFrozen: true, FreezeReason: "state machine unavailable"}}
	}
	machine.FreezeWrites(reason)
	state := machine.Snapshot()
	return StartupResult{Stage: StartupStageFailed, State: state, LastKnownGood: state}
}

func emptyStartupState(clusterID string) State {
	return State{ClusterID: clusterID, WriteFrozen: true, FreezeReason: "leader not established"}
}

func validateInitialStateRequest(request InitialStateRequest, clusterID string) error {
	if !ValidIdentity(request.Version) || len(request.Payload) == 0 || !json.Valid(request.Payload) || !ValidIdentity(request.Nonce) {
		return fmt.Errorf("version, valid JSON payload and nonce are required")
	}
	digest := request.Digest
	if digest == "" {
		digest = Digest(request.Payload)
	}
	if digest != Digest(request.Payload) || !validDigest(digest) {
		return fmt.Errorf("digest does not match payload")
	}
	if !ValidIdentity(request.Confirmation.ID) || !ValidIdentity(request.Confirmation.Actor) || (request.Confirmation.Reason != "" && !validConfirmationReason(request.Confirmation.Reason)) {
		return fmt.Errorf("administrator confirmation id and actor are required")
	}
	if !ValidIdentity(clusterID) {
		return fmt.Errorf("cluster id is invalid")
	}
	return nil
}

func validConfirmationReason(value string) bool {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func startupPayloadEmpty(state State) bool {
	return state.Revision == 0 && state.Desired.Version == "" && state.Desired.Digest == "" && len(state.Desired.Payload) == 0 && len(state.NonceLedger) == 0
}

func startupInitialStateMatches(state State, request InitialStateRequest) bool {
	digest := request.Digest
	if digest == "" {
		digest = Digest(request.Payload)
	}
	return state.Revision == 1 && state.ClusterID != "" && state.LeaderID != "" && state.Term != 0 && state.Epoch != 0 && !state.WriteFrozen &&
		state.Desired.Version == request.Version && state.Desired.Digest == digest && string(state.Desired.Payload) == string(request.Payload) &&
		len(state.NonceLedger) == 1 && state.NonceLedger[request.Nonce] == 1
}

func authorizeInitialState(ctx context.Context, authorizer InitialStateAuthorizer, request InitialStateRequest) error {
	if authorizer == nil {
		return nil
	}
	return authorizer.AuthorizeInitialState(ctx, request)
}

func startupCommitFromState(state State, nonce string) (Commit, error) {
	if !ValidIdentity(nonce) || state.NonceLedger[nonce] != state.Revision || state.Revision != 1 || state.WriteFrozen {
		return Commit{}, ErrInvalidCommit
	}
	return Commit{State: state, Fence: FenceToken{ClusterID: state.ClusterID, LeaderID: state.LeaderID, Epoch: state.Epoch, Revision: state.Revision, Digest: state.Desired.Digest, Nonce: nonce}}, nil
}

// NewInitialCommit creates the protected revision-one commit for an already
// established leader. The leadership generation is copied exactly from the
// supplied snapshot; it is never reconstructed by incrementing a fresh state
// machine from epoch one. A frozen revision-zero snapshot is accepted because
// the coordinator intentionally holds its live machine frozen until the
// caller validates the resulting fence and resumes writes.
func NewInitialCommit(clusterID string, leadership State, request InitialStateRequest) (Commit, error) {
	return newInitialCommitAt(clusterID, leadership, request, time.Now)
}

func newInitialCommitAt(clusterID string, leadership State, request InitialStateRequest, now func() time.Time) (Commit, error) {
	if err := validateInitialStateRequest(request, clusterID); err != nil {
		return Commit{}, fmt.Errorf("%w: %v", ErrStartupInitialState, err)
	}
	if leadership.ClusterID != clusterID || leadership.Revision != 0 || leadership.LeaderID == "" || leadership.Term == 0 || leadership.Epoch == 0 || !startupPayloadEmpty(leadership) {
		return Commit{}, ErrInvalidCommit
	}
	if now == nil {
		now = time.Now
	}
	updatedAt := now().UTC()
	if updatedAt.IsZero() {
		return Commit{}, fmt.Errorf("%w: initial commit timestamp is zero", ErrInvalidCommit)
	}
	digest := request.Digest
	if digest == "" {
		digest = Digest(request.Payload)
	}
	state := State{
		ClusterID: clusterID,
		LeaderID:  leadership.LeaderID,
		Term:      leadership.Term,
		Epoch:     leadership.Epoch,
		Revision:  1,
		Desired: DesiredState{
			Version: request.Version,
			Digest:  digest,
			Payload: append([]byte(nil), request.Payload...),
		},
		UpdatedAt:   updatedAt,
		NonceLedger: map[string]Revision{request.Nonce: 1},
	}
	return startupCommitFromState(state, request.Nonce)
}

func startupCommitForLeadership(clusterID string, leadership State, request InitialStateRequest) (Commit, error) {
	if leadership.WriteFrozen {
		return Commit{}, ErrInvalidCommit
	}
	return NewInitialCommit(clusterID, leadership, request)
}

func startupPayloadEquivalent(a, b State) bool {
	return a.ClusterID == b.ClusterID && a.Revision == b.Revision && a.Desired.Version == b.Desired.Version && a.Desired.Digest == b.Desired.Digest && string(a.Desired.Payload) == string(b.Desired.Payload) && sameNonceLedger(a.NonceLedger, b.NonceLedger)
}

func exactInitialConsensusCommit(ctx context.Context, consensus ConsensusBootstrap, clusterID string, request InitialStateRequest, current State) (Commit, error) {
	recovery, ok := consensus.(ConsensusCommitRecoveryStore)
	if !ok || isNilStartupDependency(recovery) {
		return Commit{}, fmt.Errorf("consensus cannot provide the exact initial commit")
	}
	commit, err := recovery.CurrentCommit(ctx, clusterID)
	if err != nil {
		return Commit{}, err
	}
	if commit.State.ClusterID != clusterID || !startupInitialStateMatches(commit.State, request) || !initialRequestMatchesCommit(request, commit) ||
		commit.State.FreezeReason != "" || commit.State.UpdatedAt.IsZero() {
		return Commit{}, ErrInvalidCommit
	}
	reconstructed, err := startupCommitFromState(commit.State, request.Nonce)
	if err != nil || !commitsEquivalent(reconstructed, commit) {
		return Commit{}, ErrInvalidCommit
	}
	if !startupPayloadEquivalent(commit.State, current) || current.WriteFrozen || current.FreezeReason != "" || current.UpdatedAt.IsZero() {
		return Commit{}, ErrInvalidCommit
	}
	if startupLeadershipEquivalent(commit.State, current) {
		if !statesEquivalent(commit.State, current) {
			return Commit{}, ErrInvalidCommit
		}
		return commit, nil
	}
	if err := validateLeadershipCheckpoint(commit.State, current); err != nil {
		return Commit{}, err
	}
	if current.UpdatedAt.Before(commit.State.UpdatedAt) {
		return Commit{}, ErrInvalidCommit
	}
	return commit, nil
}

func validateConsensusAheadRecovery(durable, consensus State, commit Commit) error {
	if durable.Revision == 0 || consensus.Revision != durable.Revision+1 || commit.State.Revision != consensus.Revision || !startupPayloadEquivalent(commit.State, consensus) {
		return ErrInvalidCommit
	}
	if !ValidIdentity(commit.State.ClusterID) || !ValidIdentity(commit.State.LeaderID) || !ValidIdentity(commit.State.Desired.Version) || !ValidIdentity(commit.Fence.Nonce) ||
		commit.State.ClusterID != durable.ClusterID || commit.State.WriteFrozen || commit.State.FreezeReason != "" || commit.State.UpdatedAt.IsZero() || len(commit.State.Desired.Payload) == 0 ||
		commit.State.Desired.Digest != Digest(commit.State.Desired.Payload) || commit.Fence.ClusterID != commit.State.ClusterID || commit.Fence.LeaderID != commit.State.LeaderID ||
		commit.Fence.Epoch != commit.State.Epoch || commit.Fence.Revision != commit.State.Revision || commit.Fence.Digest != commit.State.Desired.Digest ||
		!nonceLedgerExtends(durable.NonceLedger, commit.State.NonceLedger, commit.Fence.Nonce, commit.State.Revision) {
		return ErrInvalidCommit
	}
	if commit.State.Term < durable.Term || commit.State.Epoch < durable.Epoch {
		return ErrStaleEpoch
	}
	if commit.State.UpdatedAt.Before(durable.UpdatedAt) || consensus.UpdatedAt.Before(commit.State.UpdatedAt) {
		return ErrInvalidCommit
	}
	if commit.State.Epoch == durable.Epoch && (commit.State.Term != durable.Term || commit.State.LeaderID != durable.LeaderID) {
		return ErrInvalidCommit
	}
	if commit.State.Epoch > durable.Epoch && commit.State.Term <= durable.Term {
		return ErrStaleEpoch
	}
	if startupLeadershipEquivalent(commit.State, consensus) && !statesEquivalent(commit.State, consensus) {
		return ErrInvalidCommit
	}
	return nil
}

func nonceLedgerExtends(current, next map[string]Revision, nonce string, revision Revision) bool {
	if len(next) != len(current)+1 || next[nonce] != revision {
		return false
	}
	if _, exists := current[nonce]; exists {
		return false
	}
	for existing, existingRevision := range current {
		if next[existing] != existingRevision {
			return false
		}
	}
	return true
}

func startupLeadershipEquivalent(a, b State) bool {
	return a.ClusterID == b.ClusterID && a.LeaderID == b.LeaderID && a.Term == b.Term && a.Epoch == b.Epoch && a.Revision == b.Revision
}

func validateStartupFence(state State, fence FenceToken) error {
	if state.Revision == 0 {
		return fmt.Errorf("committed desired state is required before production readiness")
	}
	if state.WriteFrozen || state.Term == 0 || state.Epoch == 0 || state.LeaderID == "" {
		return fmt.Errorf("snapshot is frozen or has no established leader epoch")
	}
	if fence.ClusterID != state.ClusterID || fence.LeaderID != state.LeaderID || fence.Epoch != state.Epoch || fence.Revision != state.Revision || fence.Digest != state.Desired.Digest || fence.Nonce == "" {
		return fmt.Errorf("token cluster, leader, epoch, revision, digest or nonce does not match snapshot")
	}
	if revision, ok := state.NonceLedger[fence.Nonce]; !ok || revision != state.Revision {
		return fmt.Errorf("token nonce is not bound to the current snapshot revision")
	}
	return nil
}

func validStartupIdentifier(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func startupSnapshotRegresses(previous, next State) bool {
	if previous.ClusterID == "" || previous.Revision == 0 {
		return false
	}
	if next.Revision < previous.Revision || next.Epoch < previous.Epoch {
		return true
	}
	if next.Epoch == previous.Epoch && next.Term < previous.Term {
		return true
	}
	if next.Epoch == previous.Epoch && (next.Term != previous.Term || next.LeaderID != previous.LeaderID) {
		return true
	}
	if next.Epoch > previous.Epoch && next.Term <= previous.Term {
		return true
	}
	if next.Revision == previous.Revision && next.Revision > 0 {
		return next.Desired.Version != previous.Desired.Version || next.Desired.Digest != previous.Desired.Digest || string(next.Desired.Payload) != string(previous.Desired.Payload) || !sameNonceLedger(next.NonceLedger, previous.NonceLedger)
	}
	return false
}

func startupStatesEquivalent(a, b State) bool {
	if isEmptyInitialState(a) && isEmptyInitialState(b) {
		return a.ClusterID == b.ClusterID
	}
	return statesEquivalent(a, b)
}

func isNilStartupDependency(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
