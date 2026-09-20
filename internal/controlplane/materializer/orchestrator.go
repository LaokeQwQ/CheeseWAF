package materializer

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

var (
	ErrNilContext          = errors.New("materializer context is nil")
	ErrCompensationPending = errors.New("materializer runtime compensation is pending")
	ErrMissingSnapshot     = errors.New("materializer config snapshot provider is required")
	ErrMissingPrevious     = errors.New("materializer previous config snapshot provider is required")
	ErrMissingCallback     = errors.New("materializer callback is required")
	ErrMissingValidator    = errors.New("materializer current commit validator is required")
	ErrMissingJournal      = errors.New("materializer journal store is required")
)

// CurrentCommitValidator is deliberately narrower than the control-plane
// StateMachine. It is the required preflight check for exact current commits.
type CurrentCommitValidator interface {
	ValidateCurrentCommit(controlplane.Commit) error
}

// CurrentCommitGuard is an optional stronger side-effect boundary. When
// supplied, the guard must validate the commit and retain its committed-state
// read lock for the complete callback, closing the check/use window where a
// commit could change before YAML/runtime side effects.
type CurrentCommitGuard interface {
	WithCurrentCommit(controlplane.Commit, func() error) error
}

// ConfigSnapshotProvider returns the node's current complete local config.
// It must not return a control-plane desired-state document.
type ConfigSnapshotProvider func(context.Context) (*config.Config, error)

func (p ConfigSnapshotProvider) Snapshot(ctx context.Context) (*config.Config, error) {
	if p == nil {
		return nil, ErrMissingSnapshot
	}
	return p(ctx)
}

// ConfigCallback is a narrow seam for a caller-owned durable config write or
// runtime apply. The orchestrator never calls config.Save or a Handler.
type ConfigCallback func(context.Context, *config.Config) error

// ProtectionPolicyApplier materializes one committed protection-policy
// document into a node-local configuration. It is pure dependency injection:
// production wiring is intentionally left to a later integration slice.
type ProtectionPolicyApplier struct {
	validator        CurrentCommitValidator
	snapshot         ConfigSnapshotProvider
	previousSnapshot ConfigSnapshotProvider
	persistConfig    ConfigCallback
	applyRuntime     ConfigCallback
	rollbackRuntime  ConfigCallback
	journal          *JournalStore
	mu               sync.Mutex
	// compensationPrevious is intentionally process-local. Receipt/LKG carry
	// metadata only, so a restarted process cannot safely reconstruct the
	// complete prior config for runtime compensation.
	compensationPrevious *config.Config
}

// ProtectionPolicyApplierOptions contains all side-effect seams. A rollback
// callback is required because a runtime error can leave the data plane in an
// unknown state even when the local YAML write succeeded.
type ProtectionPolicyApplierOptions struct {
	Validator        CurrentCommitValidator
	Snapshot         ConfigSnapshotProvider
	PreviousSnapshot ConfigSnapshotProvider
	PersistConfig    ConfigCallback
	ApplyRuntime     ConfigCallback
	RollbackRuntime  ConfigCallback
	Journal          *JournalStore
}

// NewProtectionPolicyApplier constructs an un-wired node-local materializer.
// It does not inspect the filesystem, start a runtime, or connect to any
// control-plane store.
func NewProtectionPolicyApplier(opts ProtectionPolicyApplierOptions) (*ProtectionPolicyApplier, error) {
	if isNilValidator(opts.Validator) {
		return nil, ErrMissingValidator
	}
	if opts.Snapshot == nil {
		return nil, ErrMissingSnapshot
	}
	if opts.PreviousSnapshot == nil {
		return nil, ErrMissingPrevious
	}
	if opts.PersistConfig == nil || opts.ApplyRuntime == nil || opts.RollbackRuntime == nil {
		return nil, ErrMissingCallback
	}
	if opts.Journal == nil {
		return nil, ErrMissingJournal
	}
	return &ProtectionPolicyApplier{
		validator:        opts.Validator,
		snapshot:         opts.Snapshot,
		previousSnapshot: opts.PreviousSnapshot,
		persistConfig:    opts.PersistConfig,
		applyRuntime:     opts.ApplyRuntime,
		rollbackRuntime:  opts.RollbackRuntime,
		journal:          opts.Journal,
	}, nil
}

// Materializer is retained as a concise name for callers that do not need to
// spell out the desired-state kind.
type Materializer = ProtectionPolicyApplier

// NewMaterializer is an alias for NewProtectionPolicyApplier.
func NewMaterializer(opts ProtectionPolicyApplierOptions) (*Materializer, error) {
	return NewProtectionPolicyApplier(opts)
}

// ApplyCommitted applies one exact committed protection-policy payload. The
// mutex spans journal/LKG reads and every injected callback, so concurrent
// retries cannot duplicate runtime side effects. A control-plane commit is
// never rolled back here; only the node-local runtime may be compensated.
func (a *ProtectionPolicyApplier) ApplyCommitted(ctx context.Context, commit controlplane.Commit) error {
	if a == nil {
		return ErrMissingCallback
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// The first check gives callers an explicit preflight result. The second
	// check is the callback lease: StateMachine.WithCurrentCommit retains its
	// committed-state read lock for the complete local transaction, so the
	// commit cannot change between validation and any injected side effect.
	if err := a.validator.ValidateCurrentCommit(commit); err != nil {
		return err
	}
	return withCurrentCommit(a.validator, commit, func() error {
		return a.applyCommitted(ctx, commit)
	})
}

func withCurrentCommit(validator CurrentCommitValidator, commit controlplane.Commit, fn func() error) error {
	if guard, ok := validator.(CurrentCommitGuard); ok {
		return guard.WithCurrentCommit(commit, fn)
	}
	// Compatibility fallback for validators that predate CurrentCommitGuard.
	// New production wiring should use the guard-capable StateMachine; this
	// fallback preserves the old seam but cannot prevent a concurrent change
	// during fn.
	if err := validator.ValidateCurrentCommit(commit); err != nil {
		return err
	}
	return fn()
}

func (a *ProtectionPolicyApplier) applyCommitted(ctx context.Context, commit controlplane.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	prepared, err := NewReceipt(commit, PhasePrepared)
	if err != nil {
		return err
	}
	journal, journalErr := a.journal.LoadJournal()
	if journalErr != nil && !errors.Is(journalErr, ErrReceiptNotFound) {
		return journalErr
	}
	lkg, lkgErr := a.journal.LoadLKG()
	if lkgErr != nil && !errors.Is(lkgErr, ErrReceiptNotFound) {
		return lkgErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	hasJournal := journalErr == nil
	hasLKG := lkgErr == nil
	if err := validateIncoming(&journal, hasJournal, &lkg, hasLKG, prepared); err != nil {
		return err
	}

	// An applied journal is a completed local transaction. If LKG was the
	// final failed write, repair only LKG; never repeat PersistConfig or the
	// runtime callback.
	if hasJournal && sameCommit(journal, prepared) && journal.Phase == PhaseApplied {
		if hasLKG && sameCommit(lkg, journal) && lkg.Phase == PhaseApplied {
			return nil
		}
		return a.saveLKG(ctx, journal)
	}
	// LKG can survive a lost journal. Recreate the applied journal without
	// invoking either side-effect callback.
	if !hasJournal && hasLKG && sameCommit(lkg, prepared) && lkg.Phase == PhaseApplied {
		if err := a.journal.RestoreJournalFromLKG(lkg); err != nil {
			return err
		}
		return nil
	}

	current := (*Receipt)(nil)
	if hasJournal {
		current = &journal
	}
	if current == nil {
		if hasLKG {
			current = &lkg
		}
	}
	phase := PhasePrepared
	if current != nil && sameCommit(*current, prepared) {
		phase = current.Phase
	}
	if current == nil || !sameCommit(*current, prepared) {
		if err := a.saveJournal(ctx, current, &prepared); err != nil {
			return err
		}
		journal = prepared
		current = &journal
	}

	var previous *config.Config
	var candidate *config.Config
	loadCandidate := func() error {
		if candidate != nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		currentConfig, snapshotErr := a.snapshot.Snapshot(ctx)
		if snapshotErr != nil {
			return fmt.Errorf("read local config snapshot: %w", snapshotErr)
		}
		if phase == PhasePrepared {
			previous, err = a.previousSnapshot.Snapshot(ctx)
			if err != nil {
				return fmt.Errorf("read previous local config snapshot: %w", err)
			}
			if previous == nil {
				return ErrMissingPrevious
			}
			previous, err = config.Clone(previous)
			if err != nil {
				return fmt.Errorf("clone previous local config snapshot: %w", err)
			}
		} else if previous == nil {
			// A previous snapshot is useful for compensation but is not required
			// to apply a candidate successfully. If it is unavailable, a runtime
			// failure below remains compensation_pending and fail-closed.
			if prior, priorErr := a.previousSnapshot.Snapshot(ctx); priorErr == nil && prior != nil {
				previous, _ = config.Clone(prior)
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate, err = desiredstate.MaterializeProtectionPolicy(currentConfig, prepared.Payload)
		if err != nil {
			return err
		}
		return nil
	}

	if phase == PhasePrepared {
		if err := loadCandidate(); err != nil {
			return err
		}
		if err := a.call(ctx, a.persistConfig, candidate, "persist local config"); err != nil {
			return err
		}
		next := prepared.Clone()
		next.Phase = PhaseYAMLPersisted
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err
		}
		journal = next
		current = &journal
		phase = PhaseYAMLPersisted
	}

	if phase == PhaseCompensationPending {
		previousForCompensation := a.compensationPrevious
		if previousForCompensation == nil {
			var snapshotErr error
			previousForCompensation, snapshotErr = a.previousSnapshot.Snapshot(ctx)
			if snapshotErr != nil || previousForCompensation == nil {
				return errors.Join(ErrCompensationPending, snapshotErr)
			}
		}
		previousForCompensation, err := config.Clone(previousForCompensation)
		if err != nil {
			return errors.Join(ErrCompensationPending, err)
		}
		if err := a.call(ctx, a.rollbackRuntime, previousForCompensation, "retry runtime compensation"); err != nil {
			return errors.Join(ErrCompensationPending, err)
		}
		previous = previousForCompensation
		a.compensationPrevious = nil
		next := prepared.Clone()
		next.Phase = PhaseYAMLPersisted
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err
		}
		journal = next
		current = &journal
		phase = PhaseYAMLPersisted
	}

	if phase == PhaseYAMLPersisted {
		if err := loadCandidate(); err != nil {
			return err
		}
		if err := a.callRuntimeWithCompensation(ctx, candidate, previous, prepared, current); err != nil {
			return err
		}
		next := prepared.Clone()
		next.Phase = PhaseRuntimeApplied
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err
		}
		journal = next
		current = &journal
		phase = PhaseRuntimeApplied
	}

	if phase == PhaseRuntimeApplied {
		next := prepared.Clone()
		next.Phase = PhaseApplied
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err
		}
		return a.saveLKG(ctx, next)
	}
	return fmt.Errorf("materializer cannot resume from phase %q", phase)
}

func (a *ProtectionPolicyApplier) call(ctx context.Context, callback ConfigCallback, cfg *config.Config, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := callback(ctx, cfg); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

func (a *ProtectionPolicyApplier) callRuntimeWithCompensation(ctx context.Context, candidate, previous *config.Config, prepared Receipt, current *Receipt) error {
	applyErr := a.call(ctx, a.applyRuntime, candidate, "apply protection runtime")
	if applyErr == nil && ctx.Err() == nil {
		return nil
	}

	// A callback may perform the runtime side effect and then observe a
	// cancellation. Continue with a non-cancelable context so the node does
	// not leave an unknown data-plane state without attempting compensation.
	runtimeErr := applyErr
	if runtimeErr == nil {
		runtimeErr = ctx.Err()
	}
	continuationCtx := ctx
	if ctx.Err() != nil {
		continuationCtx = context.WithoutCancel(ctx)
	}
	if previous == nil {
		pending := prepared.Clone()
		pending.Phase = PhaseCompensationPending
		journalErr := a.saveJournal(continuationCtx, current, &pending)
		return errors.Join(runtimeErr, ErrCompensationPending, journalErr)
	}
	rollbackErr := a.call(continuationCtx, a.rollbackRuntime, previous, "rollback protection runtime")
	if rollbackErr == nil {
		return runtimeErr
	}
	a.compensationPrevious, _ = config.Clone(previous)
	pending := prepared.Clone()
	pending.Phase = PhaseCompensationPending
	journalErr := a.saveJournal(continuationCtx, current, &pending)
	return errors.Join(runtimeErr, ErrCompensationPending, rollbackErr, journalErr)
}

func (a *ProtectionPolicyApplier) saveJournal(ctx context.Context, previous, next *Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if next == nil {
		return errors.New("materializer next receipt is nil")
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if previous != nil {
		if err := ValidateTransition(previous, *next); err != nil {
			return err
		}
	}
	if err := a.journal.SaveJournal(*next); err != nil {
		return err
	}
	return nil
}

func (a *ProtectionPolicyApplier) saveLKG(ctx context.Context, receipt Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if receipt.Phase != PhaseApplied {
		return fmt.Errorf("materializer cannot save non-applied LKG phase %q", receipt.Phase)
	}
	if err := a.journal.SaveLKG(receipt); err != nil {
		return err
	}
	return nil
}

func validateIncoming(journal *Receipt, hasJournal bool, lkg *Receipt, hasLKG bool, prepared Receipt) error {
	// An applied LKG is only written after the journal reaches applied. Seeing
	// the same commit in an earlier journal phase therefore means the durable
	// mirrors disagree about whether the local transaction completed. Do not
	// replay YAML/runtime side effects or silently advance the journal; require
	// operator recovery instead.
	if hasJournal && hasLKG && sameCommit(*journal, *lkg) && lkg.Phase == PhaseApplied && journal.Phase != PhaseApplied {
		return ErrReceiptAmbiguous
	}
	if hasJournal {
		if sameCommit(*journal, prepared) {
			if journal.Phase == PhaseApplied || journal.Phase == PhaseCompensationPending || journal.Phase == PhasePrepared || journal.Phase == PhaseYAMLPersisted || journal.Phase == PhaseRuntimeApplied {
				// Resume is handled by ApplyCommitted below.
			} else {
				return ErrInvalidPhase
			}
		} else if err := ValidateTransition(journal, prepared); err != nil {
			return err
		}
	}
	if hasLKG {
		if !sameCommit(*lkg, prepared) {
			if err := ValidateTransition(lkg, prepared); err != nil {
				return err
			}
		}
	}
	return nil
}

func isNilValidator(v CurrentCommitValidator) bool {
	if v == nil {
		return true
	}
	return false
}
