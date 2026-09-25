package materializer

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

var (
	ErrNilContext                = errors.New("materializer context is nil")
	ErrCompensationPending       = errors.New("materializer runtime compensation is pending")
	ErrRuntimeStateUnknown       = errors.New("materializer runtime state is unknown")
	ErrMissingSnapshot           = errors.New("materializer config snapshot provider is required")
	ErrMissingPrevious           = errors.New("materializer previous config snapshot provider is required")
	ErrMissingCallback           = errors.New("materializer callback is required")
	ErrMissingValidator          = errors.New("materializer current commit validator is required")
	ErrMissingCurrentCommitGuard = errors.New("materializer current commit claimer is required")
	ErrMissingJournal            = errors.New("materializer journal store is required")
)

type CurrentCommitValidator interface {
	ValidateCurrentCommit(controlplane.Commit) error
}

type CurrentCommitClaimer interface {
	CurrentCommitValidator
	ClaimCurrentCommit(controlplane.Commit) error
}

type ConfigSnapshotProvider func(context.Context) (*config.Config, error)

func (p ConfigSnapshotProvider) Snapshot(ctx context.Context) (*config.Config, error) {
	if p == nil {
		return nil, ErrMissingSnapshot
	}
	return p(ctx)
}

type ConfigCallback func(context.Context, *config.Config) error

type ProtectionPolicyApplier struct {
	validator        CurrentCommitClaimer
	snapshot         ConfigSnapshotProvider
	previousSnapshot ConfigSnapshotProvider
	persistConfig    ConfigCallback
	runtime          RuntimeController
	runtimeTimeout   time.Duration
	journal          *JournalStore
}

type ProtectionPolicyApplierOptions struct {
	Validator        CurrentCommitValidator
	Snapshot         ConfigSnapshotProvider
	PreviousSnapshot ConfigSnapshotProvider
	PersistConfig    ConfigCallback
	Runtime          RuntimeController
	RuntimeTimeout   time.Duration
	// ApplyRuntime/RollbackRuntime are retained for compatibility with older
	// internal tests and callers. Production wiring must provide Runtime so it
	// has durable, queryable exact-commit receipts.
	ApplyRuntime    ConfigCallback
	RollbackRuntime ConfigCallback
	Journal         *JournalStore
}

func NewProtectionPolicyApplier(opts ProtectionPolicyApplierOptions) (*ProtectionPolicyApplier, error) {
	if isNilValidator(opts.Validator) {
		return nil, ErrMissingValidator
	}
	claimer, ok := opts.Validator.(CurrentCommitClaimer)
	if !ok || isNilCurrentCommitClaimer(claimer) {
		return nil, ErrMissingCurrentCommitGuard
	}
	if opts.Snapshot == nil {
		return nil, ErrMissingSnapshot
	}
	if opts.PreviousSnapshot == nil {
		return nil, ErrMissingPrevious
	}
	runtimeController := opts.Runtime
	if runtimeController == nil && opts.ApplyRuntime != nil && opts.RollbackRuntime != nil {
		runtimeController = &legacyRuntimeController{apply: opts.ApplyRuntime, rollback: opts.RollbackRuntime}
	}
	if opts.PersistConfig == nil || runtimeController == nil {
		return nil, ErrMissingCallback
	}
	if opts.Journal == nil {
		return nil, ErrMissingJournal
	}
	timeout := opts.RuntimeTimeout
	if timeout <= 0 {
		timeout = defaultRuntimeTimeout
	}
	return &ProtectionPolicyApplier{
		validator:        claimer,
		snapshot:         opts.Snapshot,
		previousSnapshot: opts.PreviousSnapshot,
		persistConfig:    opts.PersistConfig,
		runtime:          runtimeController,
		runtimeTimeout:   timeout,
		journal:          opts.Journal,
	}, nil
}

type legacyRuntimeController struct {
	mu             sync.Mutex
	apply          ConfigCallback
	rollback       ConfigCallback
	targetDigest   string
	previousDigest string
	currentDigest  string
}

func (c *legacyRuntimeController) Query(_ context.Context, target, previous RuntimeRequest) (RuntimeState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.targetDigest = target.ConfigDigest
	c.previousDigest = previous.ConfigDigest
	if c.currentDigest == "" {
		c.currentDigest = previous.ConfigDigest
	}
	switch c.currentDigest {
	case target.ConfigDigest:
		return RuntimeStateTarget, nil
	case previous.ConfigDigest:
		return RuntimeStatePrevious, nil
	default:
		return RuntimeStateUnknown, nil
	}
}

func (c *legacyRuntimeController) Apply(ctx context.Context, request RuntimeRequest) error {
	c.mu.Lock()
	callback := c.apply
	if request.ConfigDigest == c.previousDigest {
		callback = c.rollback
	}
	c.mu.Unlock()
	if err := callback(ctx, request.Config); err != nil {
		c.mu.Lock()
		c.currentDigest = "unknown"
		c.mu.Unlock()
		return err
	}
	c.mu.Lock()
	c.currentDigest = request.ConfigDigest
	c.mu.Unlock()
	return nil
}

type Materializer = ProtectionPolicyApplier

func NewMaterializer(opts ProtectionPolicyApplierOptions) (*Materializer, error) {
	return NewProtectionPolicyApplier(opts)
}

// ApplyCommitted takes the canonical directory lease before the short
// consensus claim. The lease, not the StateMachine lock, serializes all local
// filesystem and runtime work across applier/store instances and processes.
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
	lease, lockedCtx, err := acquireDirectoryLease(ctx, a.journal.dir)
	if err != nil {
		return err
	}
	if err := a.validator.ClaimCurrentCommit(commit); err != nil {
		_ = lease.Close()
		return err
	}
	err, pending := a.applyCommitted(lockedCtx, commit)
	if pending != nil {
		// A synchronous callback cannot be forcibly stopped. Release only the
		// process-local admission token now; retain the OS lock until the
		// callback really returns so another process cannot replay the side
		// effect while its outcome is still unknown.
		lease.ReleaseSequencer()
		go func() {
			<-pending
			_ = lease.Close()
		}()
		return err
	}
	return errors.Join(err, lease.Close())
}

func (a *ProtectionPolicyApplier) applyCommitted(ctx context.Context, commit controlplane.Commit) (error, <-chan struct{}) {
	prepared, err := NewReceipt(commit, PhasePrepared)
	if err != nil {
		return err, nil
	}
	journal, journalErr := a.journal.LoadJournalContext(ctx)
	if journalErr != nil && !errors.Is(journalErr, ErrReceiptNotFound) {
		return journalErr, nil
	}
	lkg, lkgErr := a.journal.LoadLKGContext(ctx)
	if lkgErr != nil && !errors.Is(lkgErr, ErrReceiptNotFound) {
		return lkgErr, nil
	}
	hasJournal, hasLKG := journalErr == nil, lkgErr == nil
	if err := validateIncoming(&journal, hasJournal, &lkg, hasLKG, prepared); err != nil {
		return err, nil
	}

	if hasJournal && sameCommit(journal, prepared) && journal.Phase == PhaseApplied {
		if !hasLKG || !sameReceipt(lkg, journal) {
			if err := a.journal.SaveLKGContext(ctx, journal); err != nil {
				return err, nil
			}
		}
		return a.journal.DeleteBaselineContext(ctx, prepared), nil
	}
	if !hasJournal && hasLKG && sameCommit(lkg, prepared) && lkg.Phase == PhaseApplied {
		if err := a.journal.RestoreJournalFromLKGContext(ctx, lkg); err != nil {
			return err, nil
		}
		return a.journal.DeleteBaselineContext(ctx, prepared), nil
	}

	current := (*Receipt)(nil)
	if hasJournal {
		current = &journal
	} else if hasLKG {
		current = &lkg
	}
	phase := PhasePrepared
	if current != nil && sameCommit(*current, prepared) {
		phase = current.Phase
	}
	if current == nil || !sameCommit(*current, prepared) {
		if err := a.saveJournal(ctx, current, &prepared); err != nil {
			return err, nil
		}
		journal = prepared
		current = &journal
		phase = PhasePrepared
	}

	baseline, baselineErr := a.journal.LoadBaselineContext(ctx, prepared)
	if errors.Is(baselineErr, ErrReceiptNotFound) && phase == PhasePrepared {
		baseline, err = a.captureBaseline(ctx, prepared)
		if err != nil {
			return err, nil
		}
		if err := a.journal.SaveBaselineContext(ctx, prepared, baseline); err != nil {
			return err, nil
		}
	} else if baselineErr != nil {
		return errors.Join(ErrCompensationPending, baselineErr), nil
	}
	previous, target, err := baseline.Configs(prepared)
	if err != nil {
		return err, nil
	}
	previousRequest := runtimeRequest(prepared, previous, baseline.PreviousDigest)
	targetRequest := runtimeRequest(prepared, target, baseline.TargetDigest)

	if phase == PhasePrepared {
		next := prepared.Clone()
		next.Phase = PhaseBaselinePersisted
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err, nil
		}
		journal, current, phase = next, &journal, PhaseBaselinePersisted
		current = &journal
	}
	if phase == PhaseBaselinePersisted {
		if err := a.callConfig(ctx, a.persistConfig, target, "persist local config"); err != nil {
			return err, nil
		}
		next := prepared.Clone()
		next.Phase = PhaseYAMLPersisted
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err, nil
		}
		journal = next
		current = &journal
		phase = PhaseYAMLPersisted
	}
	if phase == PhaseYAMLPersisted {
		next := prepared.Clone()
		next.Phase = PhaseRuntimeIntent
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err, nil
		}
		journal = next
		current = &journal
		phase = PhaseRuntimeIntent
	}

	if phase == PhaseCompensationPending {
		state, queryErr := a.runtimeState(ctx, targetRequest, previousRequest)
		if queryErr != nil {
			return errors.Join(ErrCompensationPending, queryErr), nil
		}
		switch state {
		case RuntimeStateTarget:
			// The target receipt proves the earlier side effect completed. Move
			// through intent so the journal transition remains explicit.
		case RuntimeStatePrevious:
		case RuntimeStateUnknown:
			return errors.Join(ErrCompensationPending, ErrRuntimeStateUnknown), nil
		default:
			return errors.Join(ErrCompensationPending, ErrRuntimeStateUnknown), nil
		}
		next := prepared.Clone()
		next.Phase = PhaseRuntimeIntent
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return errors.Join(ErrCompensationPending, err), nil
		}
		journal = next
		current = &journal
		phase = PhaseRuntimeIntent
	}

	if phase == PhaseRuntimeIntent {
		state, queryErr := a.runtimeState(ctx, targetRequest, previousRequest)
		if queryErr != nil {
			return queryErr, nil
		}
		if state == RuntimeStateUnknown {
			pending := prepared.Clone()
			pending.Phase = PhaseCompensationPending
			if err := a.saveJournal(ctx, current, &pending); err != nil {
				return errors.Join(ErrRuntimeStateUnknown, err), nil
			}
			return errors.Join(ErrCompensationPending, ErrRuntimeStateUnknown), nil
		}
		if state == RuntimeStatePrevious {
			call := a.callRuntime(ctx, targetRequest)
			if call.pending != nil {
				return call.err, call.pending
			}
			stateAfter, inspectErr := a.runtimeState(ctx, targetRequest, previousRequest)
			if inspectErr != nil {
				return errors.Join(call.err, inspectErr), nil
			}
			if stateAfter == RuntimeStateUnknown {
				pending := prepared.Clone()
				pending.Phase = PhaseCompensationPending
				if err := a.saveJournal(ctx, current, &pending); err != nil {
					return errors.Join(call.err, ErrRuntimeStateUnknown, err), nil
				}
				return errors.Join(call.err, ErrCompensationPending, ErrRuntimeStateUnknown), nil
			}
			if stateAfter == RuntimeStatePrevious {
				if call.err != nil {
					return call.err, nil
				}
				return ErrRuntimeStateUnknown, nil
			}
			state = stateAfter
		}
		if state != RuntimeStateTarget {
			return ErrRuntimeStateUnknown, nil
		}
		next := prepared.Clone()
		next.Phase = PhaseRuntimeApplied
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err, nil
		}
		journal = next
		current = &journal
		phase = PhaseRuntimeApplied
	}

	if phase == PhaseRuntimeApplied {
		next := prepared.Clone()
		next.Phase = PhaseApplied
		if err := a.saveJournal(ctx, current, &next); err != nil {
			return err, nil
		}
		if err := a.journal.SaveLKGContext(ctx, next); err != nil {
			return err, nil
		}
		if err := a.journal.DeleteBaselineContext(ctx, prepared); err != nil {
			return err, nil
		}
		return nil, nil
	}
	return fmt.Errorf("materializer cannot resume from phase %q", phase), nil
}

func (a *ProtectionPolicyApplier) captureBaseline(ctx context.Context, receipt Receipt) (Baseline, error) {
	current, err := a.snapshot.Snapshot(ctx)
	if err != nil {
		return Baseline{}, fmt.Errorf("read local config snapshot: %w", err)
	}
	previous, err := a.previousSnapshot.Snapshot(ctx)
	if err != nil {
		return Baseline{}, fmt.Errorf("read previous local config snapshot: %w", err)
	}
	if previous == nil {
		return Baseline{}, ErrMissingPrevious
	}
	target, err := desiredstate.MaterializeProtectionPolicy(current, receipt.Payload)
	if err != nil {
		return Baseline{}, err
	}
	return newBaseline(receipt, previous, target)
}

func (a *ProtectionPolicyApplier) callConfig(ctx context.Context, callback ConfigCallback, cfg *config.Config, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := callback(ctx, cfg); err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	return nil
}

type runtimeCall struct {
	err     error
	pending <-chan struct{}
}

func (a *ProtectionPolicyApplier) callRuntime(ctx context.Context, request RuntimeRequest) runtimeCall {
	if err := validateRuntimeRequest(request); err != nil {
		return runtimeCall{err: err}
	}
	callbackCtx, cancel := context.WithTimeout(ctx, a.runtimeTimeout)
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- a.runtime.Apply(callbackCtx, request)
	}()
	select {
	case err := <-result:
		cancel()
		if err != nil {
			return runtimeCall{err: fmt.Errorf("apply protection runtime: %w", err)}
		}
		return runtimeCall{}
	case <-callbackCtx.Done():
		err := callbackCtx.Err()
		cancel()
		return runtimeCall{err: fmt.Errorf("apply protection runtime: %w", err), pending: done}
	}
}

// runtimeState treats a matching durable runtime receipt as stronger evidence
// than a live query. Runtime controllers write that receipt only after their
// side effect returns successfully. On restart, this closes the interval where
// the side effect completed but the materializer journal is still at intent.
// A missing receipt remains compatible with controllers that can only query
// their runtime state; corrupt receipt data fails closed.
func (a *ProtectionPolicyApplier) runtimeState(ctx context.Context, target, previous RuntimeRequest) (RuntimeState, error) {
	receipt, err := a.journal.LoadRuntimeReceiptContext(ctx)
	if err == nil {
		if receipt.Matches(target) {
			return RuntimeStateTarget, nil
		}
	} else if !errors.Is(err, ErrReceiptNotFound) {
		return RuntimeStateUnknown, fmt.Errorf("load durable runtime receipt: %w", err)
	}
	return a.runtime.Query(ctx, target, previous)
}

func (a *ProtectionPolicyApplier) saveJournal(ctx context.Context, previous, next *Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if next == nil {
		return errors.New("materializer next receipt is nil")
	}
	if previous != nil {
		if err := ValidateTransition(previous, *next); err != nil {
			return err
		}
	}
	return a.journal.SaveJournalContext(ctx, *next)
}

func validateIncoming(journal *Receipt, hasJournal bool, lkg *Receipt, hasLKG bool, prepared Receipt) error {
	if hasJournal && hasLKG && sameCommit(*journal, *lkg) && lkg.Phase == PhaseApplied && journal.Phase != PhaseApplied {
		return ErrReceiptAmbiguous
	}
	if hasJournal {
		if sameCommit(*journal, prepared) {
			if !validPhase(journal.Phase) {
				return ErrInvalidPhase
			}
		} else if err := ValidateTransition(journal, prepared); err != nil {
			return err
		}
	}
	if hasLKG && !sameCommit(*lkg, prepared) {
		if err := ValidateTransition(lkg, prepared); err != nil {
			return err
		}
	}
	return nil
}

func isNilValidator(v CurrentCommitValidator) bool {
	return v == nil
}

func isNilCurrentCommitClaimer(claimer CurrentCommitClaimer) bool {
	if claimer == nil {
		return true
	}
	value := reflect.ValueOf(claimer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
