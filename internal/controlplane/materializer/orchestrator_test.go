package materializer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

type applierFixture struct {
	t         *testing.T
	machine   *controlplane.StateMachine
	commit    controlplane.Commit
	store     *JournalStore
	localMu   sync.Mutex
	local     config.Config
	previous  config.Config
	persisted *config.Config
	persist   func(context.Context, *config.Config) error
	runtime   func(context.Context, *config.Config) error
	rollback  func(context.Context, *config.Config) error
	persistN  int
	runtimeN  int
	rollbackN int
}

// fencingTOCTOUValidator changes the committed state after the orchestrator's
// preflight check. The lease check must reject the stale commit before any
// injected callback is entered.
type fencingTOCTOUValidator struct {
	machine     *controlplane.StateMachine
	replacement controlplane.Commit
	once        sync.Once
}

func (v *fencingTOCTOUValidator) ValidateCurrentCommit(commit controlplane.Commit) error {
	err := v.machine.ValidateCurrentCommit(commit)
	v.once.Do(func() { _ = v.machine.LoadSnapshot(v.replacement.State) })
	return err
}

func (v *fencingTOCTOUValidator) WithCurrentCommit(commit controlplane.Commit, fn func() error) error {
	return v.machine.WithCurrentCommit(commit, fn)
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
		Validator:        f.machine,
		Snapshot:         func(context.Context) (*config.Config, error) { return config.Clone(&f.local) },
		PreviousSnapshot: func(context.Context) (*config.Config, error) { return config.Clone(&f.previous) },
		PersistConfig:    func(ctx context.Context, candidate *config.Config) error { return f.persist(ctx, candidate) },
		ApplyRuntime:     func(ctx context.Context, candidate *config.Config) error { return f.runtime(ctx, candidate) },
		RollbackRuntime:  func(ctx context.Context, previous *config.Config) error { return f.rollback(ctx, previous) },
		Journal:          f.store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return applier
}

func TestApplyCommittedSuccessPreservesNodeLocalConfigAndPhases(t *testing.T) {
	f := newApplierFixture(t)
	store := f.store
	f.persist = func(_ context.Context, candidate *config.Config) error {
		f.persistN++
		prepared, err := store.LoadJournal()
		if err != nil || prepared.Phase != PhasePrepared {
			t.Fatalf("persist callback journal=%+v err=%v, want prepared", prepared, err)
		}
		f.persisted, err = config.Clone(candidate)
		if err != nil {
			return err
		}
		f.local = *f.persisted
		return nil
	}
	f.runtime = func(_ context.Context, candidate *config.Config) error {
		f.runtimeN++
		yamlPersisted, err := store.LoadJournal()
		if err != nil || yamlPersisted.Phase != PhaseYAMLPersisted {
			t.Fatalf("runtime callback journal=%+v err=%v, want yaml_persisted", yamlPersisted, err)
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
	if err != nil || journal.Phase != PhasePrepared {
		t.Fatalf("journal=%+v err=%v, want prepared", journal, err)
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
	applyCalls := 0
	f.runtime = func(_ context.Context, _ *config.Config) error {
		applyCalls++
		if applyCalls == 1 {
			return runtimeErr
		}
		return nil
	}
	applier := f.applier(t)
	if err := applier.ApplyCommitted(context.Background(), f.commit); !errors.Is(err, runtimeErr) {
		t.Fatalf("runtime error=%v, want %v", err, runtimeErr)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseYAMLPersisted {
		t.Fatalf("journal=%+v err=%v, want yaml_persisted after successful rollback", journal, err)
	}
	if f.persistN != 1 || f.rollbackN != 1 || applyCalls != 1 {
		t.Fatalf("failure callback counts persist=%d rollback=%d apply=%d", f.persistN, f.rollbackN, applyCalls)
	}
	if err := applier.ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
	}
	if f.persistN != 1 {
		t.Fatalf("retry from yaml_persisted repeated YAML persist: count=%d", f.persistN)
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
	if !errors.Is(err, ErrCompensationPending) || !errors.Is(err, rollbackErr) {
		t.Fatalf("compensation error=%v, want pending and rollback error", err)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseCompensationPending {
		t.Fatalf("journal=%+v err=%v, want compensation_pending", journal, err)
	}
	// A restarted applier has no prior full config and must not guess one.
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
	if err := applier.ApplyCommitted(context.Background(), f.commit); err != nil {
		t.Fatal(err)
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
	if f.persistN != 1 || f.runtimeN != 1 || f.rollbackN != 1 {
		t.Fatalf("post-runtime cancellation counts persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseYAMLPersisted {
		t.Fatalf("journal=%+v err=%v, want yaml_persisted after compensation", journal, err)
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
	if f.persistN != 1 || f.runtimeN != 2 || f.rollbackN != 1 {
		t.Fatalf("retry counts persist=%d runtime=%d rollback=%d", f.persistN, f.runtimeN, f.rollbackN)
	}
}

func TestApplyCommittedJournalFailureAfterPersistKeepsPreviousSnapshot(t *testing.T) {
	f := newApplierFixture(t)
	journalErr := errors.New("journal yaml transition unavailable")
	renameCalls := 0
	f.store.hooks.Rename = func(src, dst string) error {
		renameCalls++
		if renameCalls == 3 {
			return journalErr
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
	if err != nil || prepared.Phase != PhasePrepared {
		t.Fatalf("journal=%+v err=%v, want prepared", prepared, err)
	}

	// The durable write succeeded, but its phase marker did not. On retry the
	// independent previous snapshot must still be used for compensation.
	f.store.hooks.Rename = os.Rename
	runtimeErr := errors.New("runtime unavailable after journal retry")
	f.runtime = func(_ context.Context, _ *config.Config) error {
		f.runtimeN++
		return runtimeErr
	}
	f.rollback = func(_ context.Context, previous *config.Config) error {
		f.rollbackN++
		if previous == nil || previous.Protection.Policy.WebAttack == config.ProtectionLevelStrict {
			return errors.New("candidate used as rollback baseline")
		}
		return nil
	}
	if err := f.applier(t).ApplyCommitted(context.Background(), f.commit); !errors.Is(err, runtimeErr) {
		t.Fatalf("retry runtime error=%v, want %v", err, runtimeErr)
	}
	if f.rollbackN != 1 {
		t.Fatalf("rollback count=%d, want 1", f.rollbackN)
	}
	journal, err := f.store.LoadJournal()
	if err != nil || journal.Phase != PhaseYAMLPersisted {
		t.Fatalf("retry journal=%+v err=%v, want yaml_persisted", journal, err)
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

func TestNewProtectionPolicyApplierRequiresAllSeams(t *testing.T) {
	f := newApplierFixture(t)
	cases := []struct {
		name string
		edit func(*ProtectionPolicyApplierOptions)
		want error
	}{
		{"validator", func(o *ProtectionPolicyApplierOptions) { o.Validator = nil }, ErrMissingValidator},
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
