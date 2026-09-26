package materializer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

type applierFixture struct {
	t                 *testing.T
	machine           *controlplane.StateMachine
	commit            controlplane.Commit
	store             *JournalStore
	localMu           sync.Mutex
	local             config.Config
	previous          config.Config
	persisted         *config.Config
	persist           func(context.Context, *config.Config) error
	runtime           func(context.Context, *config.Config) error
	rollback          func(context.Context, *config.Config) error
	persistN          int
	runtimeN          int
	rollbackN         int
	previousSnapshotN int
}

type receiptAwareRuntime struct {
	journal    *JournalStore
	applyCalls atomic.Int32
	queryCalls atomic.Int32
}

func (r *receiptAwareRuntime) Query(context.Context, RuntimeRequest, RuntimeRequest) (RuntimeState, error) {
	r.queryCalls.Add(1)
	return RuntimeStatePrevious, nil
}

func (r *receiptAwareRuntime) Apply(context.Context, RuntimeRequest) error {
	r.applyCalls.Add(1)
	return nil
}

// fencingTOCTOUValidator changes the committed state after the orchestrator's
// preflight check. The lease check must reject the stale commit before any
// injected callback is entered.
type fencingTOCTOUValidator struct {
	machine     *controlplane.StateMachine
	replacement controlplane.Commit
	once        sync.Once
}

type preflightOnlyValidator struct{}

func (preflightOnlyValidator) ValidateCurrentCommit(controlplane.Commit) error { return nil }

type nilGuardValidator struct{}

func (*nilGuardValidator) ValidateCurrentCommit(controlplane.Commit) error { return nil }

func (*nilGuardValidator) WithCurrentCommit(controlplane.Commit, func() error) error { return nil }

func (*nilGuardValidator) ClaimCurrentCommit(controlplane.Commit) error { return nil }

func (v *fencingTOCTOUValidator) ValidateCurrentCommit(commit controlplane.Commit) error {
	err := v.machine.ValidateCurrentCommit(commit)
	v.once.Do(func() { _ = v.machine.LoadSnapshot(v.replacement.State) })
	return err
}

func (v *fencingTOCTOUValidator) WithCurrentCommit(commit controlplane.Commit, fn func() error) error {
	return v.machine.WithCurrentCommit(commit, fn)
}

func (v *fencingTOCTOUValidator) ClaimCurrentCommit(commit controlplane.Commit) error {
	err := v.machine.ValidateCurrentCommit(commit)
	v.once.Do(func() { _ = v.machine.LoadSnapshot(v.replacement.State) })
	if err != nil {
		return err
	}
	return v.machine.ClaimCurrentCommit(commit)
}

func newApplierFixture(t *testing.T) *applierFixture {
	t.Helper()
	machine, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.InstallLeadership(1, "leader-a"); err != nil {
		t.Fatal(err)
	}
	payload, digest, err := desiredstate.EncodeProtectionPolicy(config.ProtectionPolicyConfig{
		WebAttack: config.ProtectionLevelStrict, APISecurity: config.ProtectionLevelHigh,
		BotCC: config.ProtectionLevelSmart, ThreatIntel: config.ProtectionLevelLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := machine.Propose(controlplane.Proposal{
		LeaderID: "leader-a", ExpectedEpoch: 1, Version: desiredstate.Version,
		Payload: payload, Digest: digest, Nonce: "nonce-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := machine.LoadSnapshot(commit.State); err != nil {
		t.Fatal(err)
	}
	store, err := NewJournalStore(filepath.Join(t.TempDir(), "materializer"), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	local := config.Default()
	local.Setup.DataDir = "/var/lib/cheesewaf"
	local.TLS.CertFile = "/etc/cheesewaf/cert.pem"
	local.Storage.ManagementPostgreSQL.DSN = "postgres://user:password@example.invalid/management"
	local.Protection.Bot.Secret = "node-local-bot-secret"
	f := &applierFixture{t: t, machine: machine, commit: commit, store: store, local: local, previous: local}
	f.persist = func(_ context.Context, candidate *config.Config) error {
		f.persistN++
		f.persisted, err = config.Clone(candidate)
		if err != nil {
			return err
		}
		f.local = *f.persisted
		return nil
	}
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return nil
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil {
			return errors.New("nil rollback config")
		}
		f.local = *previous
		return nil
	}
	return f
}

func (f *applierFixture) applier(t *testing.T) *ProtectionPolicyApplier {
	t.Helper()
	applier, err := NewProtectionPolicyApplier(ProtectionPolicyApplierOptions{
		Validator: f.machine,
		Snapshot:  func(context.Context) (*config.Config, error) { return config.Clone(&f.local) },
		PreviousSnapshot: func(context.Context) (*config.Config, error) {
			f.previousSnapshotN++
			return config.Clone(&f.previous)
		},
		PersistConfig:   func(ctx context.Context, candidate *config.Config) error { return f.persist(ctx, candidate) },
		ApplyRuntime:    func(ctx context.Context, candidate *config.Config) error { return f.runtime(ctx, candidate) },
		RollbackRuntime: func(ctx context.Context, previous *config.Config) error { return f.rollback(ctx, previous) },
		Journal:         f.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return applier
}

func TestApplyCommittedSuccessPreservesNodeLocalConfigAndPhases(t *testing.T) {
	f := newApplierFixture(t)
	store := f.store
	f.persist = func(ctx context.Context, candidate *config.Config) error {
		f.persistN++
		prepared, err := store.LoadJournalContext(ctx)
		if err != nil || prepared.Phase != PhaseBaselinePersisted {
			t.Fatalf("persist callback journal=%+v err=%v, want baseline_persisted", prepared, err)
		}
		f.persisted, err = config.Clone(candidate)
		if err != nil {
			return err
		}
		f.local = *f.persisted
		return nil
	}
	f.runtime = func(ctx context.Context, candidate *config.Config) error {
		f.runtimeN++
		yamlPersisted, err := store.LoadJournalContext(ctx)
		if err != nil || yamlPersisted.Phase != PhaseRuntimeIntent {
			t.Fatalf("runtime callback journal=%+v err=%v, want runtime_intent", yamlPersisted, err)
		}
		if candidate.Protection.Policy.WebAttack != config.ProtectionLevelStrict {
			t.Fatalf("runtime candidate policy=%+v", candidate.Protection.Policy)
		}
		return nil
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	journal, err := store.LoadJournal()
	if err != nil || journal.Phase != PhaseApplied {
		t.Fatalf("journal=%+v err=%v, want applied", journal, err)
	}
	lkg, err := store.LoadLKG()
	if err != nil || lkg.Phase != PhaseApplied || !sameCommit(lkg, journal) {
		t.Fatalf("lkg=%+v err=%v, want applied journal", lkg, err)
	}
	if f.persistN != 1 || f.runtimeN != 1 || f.rollbackN != 0 {
		t.Fatalf("callback counts persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
	if f.local.Setup.DataDir != "/var/lib/cheesewaf" || f.local.TLS.CertFile != "/etc/cheesewaf/cert.pem" || f.local.Storage.ManagementPostgreSQL.DSN == "" || f.local.Protection.Bot.Secret != "node-local-bot-secret" {
		t.Fatal("materialization did not preserve node-local configuration")
	}
}

func TestApplyCommittedExactRetryIsIdempotent(t *testing.T) {
	f := newApplierFixture(t)
	applier := f.applier(t)
	if err := applier.ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	if err := applier.ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	if f.persistN != 1 || f.runtimeN != 1 || f.rollbackN != 0 {
		t.Fatalf("exact retry repeated callbacks: persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedRecoveryUsesDurableRuntimeReceiptBeforeQuery(t *testing.T) {
	f := newApplierFixture(t)
	prepared, err := NewReceipt(f.commit, PhasePrepared)
	if err != nil {
		t.Fatal(err)
	}
	target, err := desiredstate.MaterializeProtectionPolicy(&f.local, prepared.Payload)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := newBaseline(prepared, &f.previous, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveJournal(prepared); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveBaselineContext(context.Background(), prepared, baseline); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []Phase{PhaseBaselinePersisted, PhaseYAMLPersisted, PhaseRuntimeIntent} {
		next := prepared.Clone()
		next.Phase = phase
		if err := f.store.SaveJournal(next); err != nil {
			t.Fatal(err)
		}
	}
	targetRequest := runtimeRequest(prepared, target, baseline.TargetDigest)
	runtimeReceipt, err := NewRuntimeReceipt(targetRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveRuntimeReceiptContext(context.Background(), runtimeReceipt); err != nil {
		t.Fatal(err)
	}
	runtime := &receiptAwareRuntime{journal: f.store}
	applier, err := NewProtectionPolicyApplier(ProtectionPolicyApplierOptions{
		Validator: f.machine,
		Snapshot: func(context.Context) (*config.Config, error) {
			return config.Clone(&f.local)
		},
		PreviousSnapshot: func(context.Context) (*config.Config, error) {
			return config.Clone(&f.previous)
		},
		PersistConfig: f.persist,
		Runtime:       runtime,
		Journal:       f.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	if got := runtime.applyCalls.Load(); got != 0 {
		t.Fatalf("recovery replayed runtime side effect %d times", got)
	}
	if got := runtime.queryCalls.Load(); got != 0 {
		t.Fatalf("recovery queried runtime despite exact durable receipt %d times", got)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseApplied {
		t.Fatalf("journal=%+v err=%v, want applied", journal, err)
	}
}

func TestApplyCommittedRejectsStaleCurrentCommit(t *testing.T) {
	f := newApplierFixture(t)
	old := f.commit
	second, err := f.machine.Propose(controlplane.Proposal{
		LeaderID: "leader-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: desiredstate.Version,
		Payload: old.State.Desired.Payload, Digest: old.State.Desired.Digest, Nonce: "nonce-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.machine.LoadSnapshot(second.State); err != nil {
		t.Fatal(err)
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), old); !errors.Is(err, controlplane.ErrInvalidCommit) {
		t.Fatalf("stale commit error=%v, want ErrInvalidCommit", err)
	}
	if f.persistN != 0 || f.runtimeN != 0 {
		t.Fatal("stale commit reached callbacks")
	}
}

func TestApplyCommittedRejectsCommitChangedAfterPreflight(t *testing.T) {
	f := newApplierFixture(t)
	old := f.commit
	second, err := f.machine.Propose(controlplane.Proposal{
		LeaderID: "leader-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: desiredstate.Version,
		Payload: old.State.Desired.Payload, Digest: old.State.Desired.Digest, Nonce: "nonce-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	validator := &fencingTOCTOUValidator{machine: f.machine, replacement: second}
	applier, err := NewProtectionPolicyApplier(ProtectionPolicyApplierOptions{
		Validator: validator, Snapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.local) },
		PreviousSnapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.previous) },
		PersistConfig:    f.persist, ApplyRuntime: f.runtime, RollbackRuntime: f.rollback, Journal: f.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := applier.ApplyCommitted(context.Background(), old); !errors.Is(err, controlplane.ErrInvalidCommit) {
		t.Fatalf("post-preflight stale commit error=%v, want ErrInvalidCommit", err)
	}
	if f.persistN != 0 || f.runtimeN != 0 || f.rollbackN != 0 {
		t.Fatalf("stale commit reached callbacks: persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedPersistFailureLeavesPreparedJournal(t *testing.T) {
	f := newApplierFixture(t)
	wantErr := errors.New("disk full")
	f.persist = func(_ context.Context, _ *config.Config) error {
		f.persistN++
		return wantErr
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); !errors.Is(err, wantErr) {
		t.Fatalf("persist error=%v, want %v", err, wantErr)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseBaselinePersisted {
		t.Fatalf("journal=%+v err=%v, want baseline_persisted", journal, err)
	}
	if _, err := f.store.LoadLKG(); !errors.Is(err, ErrReceiptNotFound) {
		t.Fatalf("lkg err=%v, want missing", err)
	}
	if f.runtimeN != 0 {
		t.Fatal("runtime callback called after persist failure")
	}
}

func TestApplyCommittedRuntimeFailureCompensatesAndRetries(t *testing.T) {
	f := newApplierFixture(t)
	runtimeErr := errors.New("runtime unavailable")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	applier := f.applier(t)
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, runtimeErr) || !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("runtime error=%v, want runtime error and pending compensation", err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("journal=%+v err=%v, want compensation_pending", journal, err)
	}
	if f.persistN != 1 || f.rollbackN != 0 || f.runtimeN != 1 {
		t.Fatalf("failure callback counts persist=%d rollback=%d runtime=%d", f.persistN, f.rollbackN, f.runtimeN)
	}
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) || !errors.Is(err, ErrRuntimeStateUnknown) {
		t.Fatalf("unknown retry error=%v, want fail-closed pending", err)
	}
	if f.persistN != 1 || f.rollbackN != 0 || f.runtimeN != 1 {
		t.Fatalf("unknown retry mutated runtime: persist=%d rollback=%d runtime=%d", f.persistN, f.rollbackN, f.runtimeN)
	}
}

func TestApplyCommittedYAMLPersistedRetryUsesExactCommitBoundPrevious(t *testing.T) {
	f := newApplierFixture(t)
	runtimeErr := errors.New("runtime unavailable twice")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil || previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return errors.New("rollback received candidate instead of exact previous")
		}
		return nil
	}
	applier := f.applier(t)
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, runtimeErr) || !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("first runtime error=%v, want runtime error with pending compensation", err)
	}
	// A non-authoritative provider can observe the candidate after YAML has been
	// persisted. The same applier must use its retained exact baseline instead.
	f.previous = f.local
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) || !errors.Is(err, ErrRuntimeStateUnknown) {
		t.Fatalf("second runtime error=%v, want fail-closed pending", err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("journal=%+v err=%v, want compensation_pending", journal, err)
	}
	if f.previousSnapshotN != 1 || f.rollbackN != 0 || f.runtimeN != 1 {
		t.Fatalf("retry callbacks previous snapshots=%d rollback=%d runtime=%d, want 1/0/1", f.previousSnapshotN, f.rollbackN, f.runtimeN)
	}
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatal(err)
	}
	if f.runtimeN != 1 || f.rollbackN != 0 {
		t.Fatalf("unknown state caused replay callbacks runtime=%d rollback=%d", f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedDoesNotUseDifferentCommitCompensationBaseline(t *testing.T) {
	f := newApplierFixture(t)
	runtimeErr := errors.New("runtime unavailable for commit A")
	rollbackErr := errors.New("rollback unavailable for commit A")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	f.rollback = func(_ context.Context, _ *config.Config) error {
		f.rollbackN++
		return rollbackErr
	}
	applier := f.applier(t)
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("commit A error=%v, want ErrCompensationPending", err)
	}

	commitB, err := f.machine.Propose(controlplane.Proposal{
		LeaderID: "leader-a", ExpectedEpoch: 1, ExpectedRevision: 1, Version: desiredstate.Version,
		Payload: f.commit.State.Desired.Payload, Digest: f.commit.State.Desired.Digest, Nonce: "nonce-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.machine.LoadSnapshot(commitB.State); err != nil {
		t.Fatal(err)
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		return fmt.Errorf("commit B must not rollback with commit A baseline: %+v", previous.Protection.Policy)
	}
	if err := applier.ApplyCommitted(context.Background(), commitB); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("commit B error=%v, want ErrCompensationPending", err)
	}
	if f.rollbackN != 0 || f.runtimeN != 1 {
		t.Fatalf("commit B used commit A compensation state: rollback=%d runtime=%d, want unchanged 0/1", f.rollbackN, f.runtimeN)
	}
}

func TestApplyCommittedRetainsBaselineWhenPendingJournalRecoveryFails(t *testing.T) {
	f := newApplierFixture(t)
	runtimeErr := errors.New("runtime unavailable")
	rollbackErr := errors.New("rollback unavailable")
	runtimeCalls := 0
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		runtimeCalls++
		if runtimeCalls == 1 {
			return runtimeErr
		}
		return nil
	}
	f.rollback = func(_ context.Context, _ *config.Config) error {
		f.rollbackN++
		return rollbackErr
	}
	applier := f.applier(t)
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("initial error=%v, want ErrCompensationPending", err)
	}

	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil || previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return errors.New("unsafe compensation snapshot")
		}
		return nil
	}
	journalErr := errors.New("journal compensation recovery unavailable")
	f.store.hooks.Rename = func(string, string) error { return journalErr }
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("pending recovery error=%v, want pending", err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("journal=%+v err=%v, want compensation_pending", journal, err)
	}

	f.store.hooks.Rename = os.Rename
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("retry after unknown state: %v", err)
	}
	if f.rollbackN != 0 || f.runtimeN != 1 {
		t.Fatalf("unknown state caused callbacks: rollback=%d runtime=%d", f.rollbackN, f.runtimeN)
	}
}

func TestApplyCommittedRestartFromYAMLPersistedUsesDurablePreviousBaseline(t *testing.T) {
	f := newApplierFixture(t)
	prepared, err := NewReceipt(f.commit, PhasePrepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveJournal(prepared); err != nil {
		t.Fatal(err)
	}
	candidate, err := desiredstate.MaterializeProtectionPolicy(&f.local, f.commit.State.Desired.Payload)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := newBaseline(prepared, &f.previous, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SaveBaselineContext(context.Background(), prepared, baseline); err != nil {
		t.Fatal(err)
	}
	baselinePersisted := prepared.Clone()
	baselinePersisted.Phase = PhaseBaselinePersisted
	if err := f.store.SaveJournal(baselinePersisted); err != nil {
		t.Fatal(err)
	}
	yamlPersisted := prepared.Clone()
	yamlPersisted.Phase = PhaseYAMLPersisted
	if err := f.store.SaveJournal(yamlPersisted); err != nil {
		t.Fatal(err)
	}
	f.local = *candidate
	f.previous = *candidate
	runtimeErr := errors.New("runtime unavailable after yaml recovery")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return fmt.Errorf("unsafe candidate used as rollback baseline: %+v", previous.Protection.Policy)
		}
		return nil
	}

	err = f.applier(t).ApplyCommitted(context.Background(), f.commit)
	if !errors.Is(err, runtimeErr) || !errors.Is(err, ErrRuntimeStateUnknown) {
		t.Fatalf("recovered runtime error=%v, want runtime error and unknown-state recovery", err)
	}
	journal, journalErr := f.store.LoadJournal()
	if journalErr != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("journal=%+v err=%v, want compensation_pending", journal, journalErr)
	}
	if f.previousSnapshotN != 0 || f.rollbackN != 0 {
		t.Fatalf("unknown state caused compensation: previous snapshots=%d rollback=%d", f.previousSnapshotN, f.rollbackN)
	}
	if f.persistN != 0 || f.runtimeN != 1 {
		t.Fatalf("yaml recovery callbacks persist=%d runtime=%d, want 0/1", f.persistN, f.runtimeN)
	}
}

func TestApplyCommittedRuntimeFailureRollbackFailureIsFailClosed(t *testing.T) {
	f := newApplierFixture(t)
	runtimeErr := errors.New("runtime unavailable")
	rollbackErr := errors.New("rollback unavailable")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil || previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			t.Errorf("rollback received candidate or nil previous policy=%+v", previous)
		}
		return rollbackErr
	}
	applier := f.applier(t)
	err := applier.ApplyCommitted(context.Background(), f.commit)
	if !errors.Is(err, ErrCompensationPending) || !errors.Is(err, runtimeErr) {
		t.Fatalf("compensation error=%v, want pending and runtime error", err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("journal=%+v err=%v, want compensation_pending", journal, err)
	}
	// A restarted applier must recover the exact durable prior config rather
	// than depending on process-local memory.
	restarted := f.applier(t)
	if err := restarted.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("restarted compensation error=%v, want ErrCompensationPending", err)
	}
	// The retained previous snapshot makes an in-process retry safe.
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil || previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return errors.New("unsafe compensation snapshot")
		}
		return nil
	}
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return nil
	}
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatal(err)
	}
	if f.persistN != 1 || f.runtimeN != 2 || f.rollbackN != 0 {
		t.Fatalf("unknown state caused callbacks persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedRestartRecoversWithExactDurablePrevious(t *testing.T) {
	f := newApplierFixture(t)
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return errors.New("runtime unavailable")
	}
	f.rollback = func(_ context.Context, _ *config.Config) error {
		f.rollbackN++
		return errors.New("rollback unavailable")
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); !errors.Is(err, ErrCompensationPending) {
		t.Fatalf("initial failure error=%v, want ErrCompensationPending", err)
	}

	// Simulate a process restart. The second applier must use the persisted
	// baseline and exact runtime receipt state, not the changed provider value.
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		return errors.New("restart must not attempt rollback without exact previous config")
	}
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return nil
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatalf("restart durable recovery error=%v", err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseApplied {
		t.Fatalf("restart journal=%+v err=%v, want applied", journal, err)
	}
	if f.persistN != 1 || f.runtimeN != 2 || f.rollbackN != 0 {
		t.Fatalf("restart recovery counts persist=%d runtime=%d rollback=%d, want 1/2/0", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedCancellationAfterRuntimeSideEffectCompensates(t *testing.T) {
	f := newApplierFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		cancel()
		return nil
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil || previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return errors.New("unsafe compensation snapshot")
		}
		return nil
	}
	applier := f.applier(t)
	if err := applier.ApplyCommitted(ctx, f.commit); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled post-runtime error=%v, want context.Canceled", err)
	}
	if f.persistN != 1 || f.runtimeN != 1 || f.rollbackN != 0 {
		t.Fatalf("post-runtime cancellation counts persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseRuntimeIntent {
		t.Fatalf("journal=%+v err=%v, want runtime_intent after timeout", journal, err)
	}

	// A fresh context can retry the still-persisted candidate without repeating
	// YAML persistence; the canceled attempt must not be mistaken for applied.
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return nil
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	if f.persistN != 1 || f.runtimeN != 2 || f.rollbackN != 0 {
		t.Fatalf("retry counts persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedRecoveryAfterPersistUsesDurablePrevious(t *testing.T) {
	f := newApplierFixture(t)
	journalErr := errors.New("journal yaml transition unavailable")
	f.store.hooks.Rename = func(src, dst string) error {
		if strings.HasSuffix(dst, JournalPrimaryName) {
			if data, readErr := os.ReadFile(src); readErr == nil {
				if receipt, decodeErr := decodeReceipt(data); decodeErr == nil && receipt.Phase == PhaseYAMLPersisted {
					return journalErr
				}
			}
		}
		return os.Rename(src, dst)
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); !errors.Is(err, journalErr) {
		t.Fatalf("journal transition error=%v, want %v", err, journalErr)
	}
	if f.persistN != 1 || f.runtimeN != 0 {
		t.Fatalf("failure counts persist=%d runtime=%d", f.persistN, f.runtimeN)
	}
	prepared, err := f.store.LoadJournal()
	if err != nil || prepared.Phase != PhaseBaselinePersisted {
		t.Fatalf("journal=%+v err=%v, want baseline_persisted", prepared, err)
	}

	// The durable write may have succeeded, but its phase marker did not. A
	// restarted applier cannot distinguish that crash window from a pre-write
	// persist failure, so it must not treat a provider result as a durable prior
	// config. This fixture makes the provider observe the candidate YAML.
	f.store.hooks.Rename = os.Rename
	f.previous = f.local
	runtimeErr := errors.New("runtime unavailable after journal retry")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return fmt.Errorf("unsafe candidate rollback invoked with %+v", previous.Protection.Policy)
		}
		return nil
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); !errors.Is(err, runtimeErr) || !errors.Is(err, ErrRuntimeStateUnknown) {
		t.Fatalf("retry runtime error=%v, want runtime error and recovered unknown state", err)
	}
	if f.previousSnapshotN != 1 || f.rollbackN != 0 {
		t.Fatalf("unknown state caused compensation: previous snapshots=%d rollback=%d", f.previousSnapshotN, f.rollbackN)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("retry journal=%+v err=%v, want compensation_pending", journal, err)
	}
	if f.persistN != 2 || f.runtimeN != 1 {
		t.Fatalf("prepared recovery callbacks persist=%d runtime=%d, want 2/1", f.persistN, f.runtimeN)
	}
}

func TestApplyCommittedRestoresJournalFromAppliedLKG(t *testing.T) {
	f := newApplierFixture(t)
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.store.Directory(), JournalPrimaryName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.store.Directory(), JournalBackupName)); err != nil {
		t.Fatal(err)
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseApplied {
		t.Fatalf("restored journal=%+v err=%v, want applied", journal, err)
	}
	if f.persistN != 1 || f.runtimeN != 1 || f.rollbackN != 0 {
		t.Fatalf("journal recovery repeated callbacks: persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedHonorsCanceledContext(t *testing.T) {
	f := newApplierFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.applier(t).ApplyCommitted(ctx, f.commit); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error=%v, want context.Canceled", err)
	}
	if f.persistN != 0 || f.runtimeN != 0 || f.rollbackN != 0 {
		t.Fatal("canceled context reached a callback")
	}
	if _, err := f.store.LoadJournal(); !errors.Is(err, ErrReceiptNotFound) {
		t.Fatalf("canceled context wrote journal: %v", err)
	}
}

func TestApplyCommittedSerializesConcurrentRetries(t *testing.T) {
	f := newApplierFixture(t)
	var persists, runtimes atomic.Int32
	f.persist = func(_ context.Context, candidate *config.Config) error {
		persists.Add(1)
		f.localMu.Lock()
		defer f.localMu.Unlock()
		var err error
		f.persisted, err = config.Clone(candidate)
		if err == nil {
			f.local = *f.persisted
		}
		return err
	}
	f.runtime = func(_ context.Context, _ *config.Config) error {
		runtimes.Add(1)
		return nil
	}
	applier := f.applier(t)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := applier.ApplyCommitted(context.Background(), f.commit); err != nil {
				t.Errorf("concurrent apply: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := persists.Load(); got != 1 {
		t.Fatalf("persist callback count=%d, want 1", got)
	}
	if got := runtimes.Load(); got != 1 {
		t.Fatalf("runtime callback count=%d, want 1", got)
	}
}

func TestApplyCommittedTimeoutReleasesSequencerButRetainsOSLease(t *testing.T) {
	f := newApplierFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	f.runtime = func(_ context.Context, _ *config.Config) error {
		close(started)
		<-release
		return nil
	}
	applier, err := NewProtectionPolicyApplier(ProtectionPolicyApplierOptions{
		Validator: f.machine, Snapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.local) },
		PreviousSnapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.previous) },
		PersistConfig:    f.persist, ApplyRuntime: f.runtime, RollbackRuntime: f.rollback,
		RuntimeTimeout: 10 * time.Millisecond, Journal: f.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- applier.ApplyCommitted(context.Background(), f.commit) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime callback did not start")
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout error=%v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout did not return to caller")
	}
	sequencer := sequencerFor(f.store.Directory())
	select {
	case token := <-sequencer.token:
		sequencer.token <- token
	default:
		t.Fatal("timeout retained process-local sequencer token")
	}
	other, err := NewJournalStore(f.store.Directory(), Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	blockedCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := other.LoadJournalContext(blockedCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("long callback did not retain OS lease, err=%v", err)
	}
	close(release)
}

func TestNewProtectionPolicyApplierRequiresAllSeams(t *testing.T) {
	f := newApplierFixture(t)
	cases := []struct {
		name string
		edit func(*ProtectionPolicyApplierOptions)
		want error
	}{
		{"validator", func(o *ProtectionPolicyApplierOptions) { o.Validator = nil }, ErrMissingValidator},
		{"current commit guard", func(o *ProtectionPolicyApplierOptions) { o.Validator = preflightOnlyValidator{} }, ErrMissingCurrentCommitGuard},
		{"nil current commit guard", func(o *ProtectionPolicyApplierOptions) { var guard *nilGuardValidator; o.Validator = guard }, ErrMissingCurrentCommitGuard},
		{"snapshot", func(o *ProtectionPolicyApplierOptions) { o.Snapshot = nil }, ErrMissingSnapshot},
		{"previous snapshot", func(o *ProtectionPolicyApplierOptions) { o.PreviousSnapshot = nil }, ErrMissingPrevious},
		{"callback", func(o *ProtectionPolicyApplierOptions) { o.ApplyRuntime = nil }, ErrMissingCallback},
		{"journal", func(o *ProtectionPolicyApplierOptions) { o.Journal = nil }, ErrMissingJournal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := ProtectionPolicyApplierOptions{Validator: f.machine, Snapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.local) }, PreviousSnapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.previous) }, PersistConfig: f.persist, ApplyRuntime: f.runtime, RollbackRuntime: f.rollback, Journal: f.store}
			tc.edit(&opts)
			if _, err := NewProtectionPolicyApplier(opts); !errors.Is(err, tc.want) {
				t.Fatalf("constructor error=%v, want %v", err, tc.want)
			}
		})
	}
	if _, err := NewProtectionPolicyApplier(ProtectionPolicyApplierOptions{Validator: f.machine, Snapshot: func(context.Context) (*config.Config, error) { return nil, fmt.Errorf("unused") }, PreviousSnapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.previous) }, PersistConfig: f.persist, ApplyRuntime: f.runtime, RollbackRuntime: f.rollback, Journal: f.store}); err != nil {
		t.Fatalf("valid constructor error=%v", err)
	}
}
