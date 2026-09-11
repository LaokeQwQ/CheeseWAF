// Package migration contains the protected temporary-to-production cut-over
// contract. It deliberately has no database, network, or WAF data-plane
// implementation; adapters are injected by the caller and can be replaced by
// deterministic fakes in tests.
package migration

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
	"unicode"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
)

const (
	TemporaryProfile  = "temporary"
	ProductionProfile = "production"
	WarningDelay      = approval.WarningDelay
)

var (
	ErrInvalidOptions                  = errors.New("invalid migration options")
	ErrInvalidConfirmation             = errors.New("invalid migration confirmation")
	ErrWarningDelay                    = approval.ErrWarningDelay
	ErrConfirmationPhrase              = approval.ErrConfirmationPhrase
	ErrSecondConfirmation              = approval.ErrSecondConfirmation
	ErrPasswordConfirmation            = approval.ErrPasswordConfirmation
	ErrConfirmationRejected            = errors.New("migration confirmation rejected")
	ErrPrerequisiteUnavailable         = errors.New("production prerequisite unavailable")
	ErrSourceUnavailable               = errors.New("temporary source unavailable")
	ErrProfileMismatch                 = errors.New("migration requires temporary source profile")
	ErrTemporaryInvalidationIncomplete = errors.New("temporary state invalidation is incomplete")
	ErrRollbackFailed                  = errors.New("migration rollback failed")
	ErrMigrationInProgress             = errors.New("migration already in progress")
	ErrTransactionUnavailable          = errors.New("production migration transaction unavailable")
	ErrManagementStateMigration        = errors.New("management state migration failed")
	ErrTokenMetadataMigration          = errors.New("token metadata migration failed")
	ErrTokenMetadataRotation           = errors.New("token metadata rotation failed")
	ErrCommitFailed                    = errors.New("production migration commit failed")
	// ErrCommitOutcomeUnknown means the production transaction may already be
	// durable. Callers must keep temporary credentials invalidated and enter the
	// explicit recovery workflow; restoring temporary state could create two
	// authoritative management stores.
	ErrCommitOutcomeUnknown = errors.New("production migration commit outcome is unknown")
)

// Failure is a safe, typed error. Code is deliberately stable and raw backend
// errors are never included because they may contain DSNs, credentials, or
// provider topology.
type Failure struct {
	Kind error
	Code string
}

func (e Failure) Error() string {
	if e.Code == "" {
		return e.Kind.Error()
	}
	return e.Kind.Error() + ": " + e.Code
}

func (e Failure) Unwrap() error { return e.Kind }

func safeFailure(kind error, code string) error { return Failure{Kind: kind, Code: code} }

// Snapshot is an opaque, immutable view exported from temporary mode. The
// source adapter owns its interpretation; TokenMetadata is passed to the
// production transaction before it is rotated.
type Snapshot struct {
	ID           string
	ConfigDigest string
	// ManagementState is an opaque snapshot of the complete temporary
	// management database. It may contain credential hashes and TOTP secrets and
	// must therefore remain in process memory only.
	ManagementState []byte
	TokenMetadata   []byte
}

// InvalidationReceipt proves that every temporary security artifact was
// invalidated before production is committed.
type InvalidationReceipt struct {
	Sessions bool
	Setup    bool
	Join     bool
	CAPTCHA  bool
	Locks    bool
}

func (r InvalidationReceipt) Complete() bool {
	return r.Sessions && r.Setup && r.Join && r.CAPTCHA && r.Locks
}

// TemporarySource exports and fences the current temporary state. Restore is
// required to be idempotent so a failed cut-over can safely return to the
// last-known-good temporary mode.
type TemporarySource interface {
	Profile(context.Context) (string, error)
	Snapshot(context.Context) (Snapshot, error)
	InvalidateTemporaryState(context.Context) (InvalidationReceipt, error)
	RestoreTemporaryState(context.Context, Snapshot, InvalidationReceipt) error
}

// Prerequisite is a fail-closed health probe for one production dependency.
// PostgreSQL, native-raft, and Redis are all required for the cut-over even
// when temporary mode itself does not use them.
type Prerequisite interface {
	Check(context.Context) error
}

// ProductionTransaction is an atomic target-side migration. Implementations
// must keep metadata writes and profile activation rollbackable until Commit.
type ProductionTransaction interface {
	MigrateTokenMetadata(context.Context, Snapshot) error
	RotateTokenMetadata(context.Context, Snapshot) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

// ManagementStateTransaction is the complete migration capability implemented
// by runtime targets. The narrower ProductionTransaction method remains for
// compatibility with contract-only adapters, but production wiring must expose
// this interface so the cut-over cannot silently migrate token metadata alone.
type ManagementStateTransaction interface {
	MigrateManagementState(context.Context, Snapshot) error
}

// ProductionTarget opens a rollback-capable production transaction.
type ProductionTarget interface {
	Begin(context.Context, Snapshot) (ProductionTransaction, error)
}

// ConfirmationRequest is the caller-provided second-confirmation material.
// Identity and phrase fields are intentionally compared exactly; callers must
// not trim or silently normalize them.
type ConfirmationRequest struct {
	Actor              string
	SessionID          string
	Language           string
	Phrase             string
	WarningReadAt      time.Time
	PasswordConfirmed  bool
	TOTPConfirmed      bool
	SecondConfirmation bool
	ThirdConfirmation  bool
	ConfirmationID     string
	Local              bool
}

// ConfirmationProvider performs the adapter-specific password/TOTP check.
// Structural checks remain in this package so an adapter cannot weaken them.
type ConfirmationProvider interface {
	Confirm(context.Context, ConfirmationRequest) error
}

// Options wires the migration contract. All external systems are explicit;
// a nil PostgreSQL, native-raft, or Redis prerequisite is an error.
type Options struct {
	Source     TemporarySource
	Target     ProductionTarget
	PostgreSQL Prerequisite
	NativeRaft Prerequisite
	Redis      Prerequisite
	Confirmer  ConfirmationProvider
	Now        func() time.Time
}

// Result describes only the security-relevant migration milestones. It does
// not expose credentials, DSNs, or temporary state contents.
type Result struct {
	SnapshotID              string
	MigratedAt              time.Time
	TemporaryInvalidated    bool
	ManagementStateMigrated bool
	TokenMetadataMigrated   bool
	TokensRotated           bool
	Committed               bool
}

// Runner executes one migration at a time. The mutex prevents two operators
// from concurrently invalidating and restoring the same temporary state.
type Runner struct {
	opts Options
	mu   sync.Mutex
}

func New(opts Options) *Runner { return &Runner{opts: opts} }

func (r *Runner) Run(ctx context.Context, confirmation ConfirmationRequest) (Result, error) {
	if r == nil {
		return Result{}, ErrInvalidOptions
	}
	if !r.mu.TryLock() {
		return Result{}, ErrMigrationInProgress
	}
	defer r.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateOptions(r.opts); err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if r.opts.Now != nil {
		now = r.opts.Now().UTC()
	}
	if err := validateConfirmation(confirmation, now); err != nil {
		return Result{}, err
	}
	if err := r.opts.Confirmer.Confirm(ctx, confirmation); err != nil {
		return Result{}, safeFailure(ErrConfirmationRejected, "provider rejected confirmation")
	}
	if err := checkContext(ctx); err != nil {
		return Result{}, err
	}
	if err := checkPrerequisites(ctx, r.opts); err != nil {
		return Result{}, err
	}
	profile, err := r.opts.Source.Profile(ctx)
	if err != nil {
		return Result{}, safeFailure(ErrSourceUnavailable, "profile probe failed")
	}
	if profile != TemporaryProfile {
		return Result{}, safeFailure(ErrProfileMismatch, "source profile is not temporary")
	}
	snapshot, err := r.opts.Source.Snapshot(ctx)
	if err != nil {
		return Result{}, safeFailure(ErrSourceUnavailable, "temporary snapshot failed")
	}
	if err := checkContext(ctx); err != nil {
		return Result{}, err
	}
	receipt, err := r.opts.Source.InvalidateTemporaryState(ctx)
	if err != nil {
		restoreErr := r.opts.Source.RestoreTemporaryState(cleanupContext(ctx), snapshot, receipt)
		return Result{}, joinRollback(safeFailure(ErrSourceUnavailable, "temporary invalidation failed"), restoreErr)
	}
	if !receipt.Complete() {
		restoreErr := r.opts.Source.RestoreTemporaryState(cleanupContext(ctx), snapshot, receipt)
		return Result{}, errors.Join(ErrTemporaryInvalidationIncomplete, rollbackError(restoreErr))
	}

	result := Result{SnapshotID: snapshot.ID, MigratedAt: now, TemporaryInvalidated: true}
	tx, err := r.opts.Target.Begin(ctx, snapshot)
	if err != nil {
		return Result{}, rollbackAfterPrepare(ctx, r.opts.Source, snapshot, receipt, safeFailure(ErrTransactionUnavailable, "target transaction could not begin"))
	}
	if isNilInterface(tx) {
		return Result{}, rollbackAfterPrepare(ctx, r.opts.Source, snapshot, receipt, ErrTransactionUnavailable)
	}
	fail := func(cause error) (Result, error) {
		return Result{}, rollbackTransaction(ctx, tx, r.opts.Source, snapshot, receipt, cause)
	}
	if err := checkContext(ctx); err != nil {
		return fail(err)
	}
	if managementTx, ok := tx.(ManagementStateTransaction); ok {
		if err := managementTx.MigrateManagementState(ctx, snapshot); err != nil {
			return fail(safeFailure(ErrManagementStateMigration, "management state import failed"))
		}
		result.ManagementStateMigrated = true
	} else {
		if len(snapshot.ManagementState) != 0 {
			return fail(safeFailure(ErrManagementStateMigration, "target does not support complete management state import"))
		}
	}
	if err := tx.MigrateTokenMetadata(ctx, snapshot); err != nil {
		return fail(safeFailure(ErrTokenMetadataMigration, "token metadata import failed"))
	}
	result.TokenMetadataMigrated = true
	if err := tx.RotateTokenMetadata(ctx, snapshot); err != nil {
		return fail(safeFailure(ErrTokenMetadataRotation, "token metadata rotation failed"))
	}
	result.TokensRotated = true
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, ErrCommitOutcomeUnknown) {
			return result, errors.Join(safeFailure(ErrCommitFailed, "production commit requires recovery"), ErrCommitOutcomeUnknown)
		}
		return fail(safeFailure(ErrCommitFailed, "target transaction commit failed"))
	}
	result.Committed = true
	return result, nil
}

func validateOptions(opts Options) error {
	if isNilInterface(opts.Source) || isNilInterface(opts.Target) || isNilInterface(opts.Confirmer) {
		return ErrInvalidOptions
	}
	return nil
}

func checkPrerequisites(ctx context.Context, opts Options) error {
	checks := []struct {
		name  string
		probe Prerequisite
	}{
		{"postgresql", opts.PostgreSQL},
		{"native-raft", opts.NativeRaft},
		{"redis", opts.Redis},
	}
	for _, check := range checks {
		if isNilInterface(check.probe) {
			return safeFailure(ErrPrerequisiteUnavailable, check.name+" is not configured")
		}
		if err := check.probe.Check(ctx); err != nil {
			return safeFailure(ErrPrerequisiteUnavailable, check.name+" health check failed")
		}
	}
	return nil
}

func validateConfirmation(c ConfirmationRequest, now time.Time) error {
	for name, value := range map[string]string{"actor": c.Actor, "session": c.SessionID, "confirmation": c.ConfirmationID} {
		if err := strictIdentity(value); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrInvalidConfirmation, name, err)
		}
	}
	language, err := approval.NormalizeConfirmationLanguage(c.Language)
	if err != nil || language != c.Language {
		return errors.Join(ErrInvalidConfirmation, approval.ErrConfirmationLanguage)
	}
	phrase, err := approval.ExpectedConfirmationPhrase(language)
	if err != nil || c.Phrase != phrase {
		return errors.Join(ErrInvalidConfirmation, ErrConfirmationPhrase)
	}
	if !c.Local {
		return errors.Join(ErrInvalidConfirmation, approval.ErrLocalConfirmation)
	}
	if c.WarningReadAt.IsZero() || c.WarningReadAt.After(now) || now.Sub(c.WarningReadAt) < WarningDelay {
		return errors.Join(ErrInvalidConfirmation, ErrWarningDelay)
	}
	if !c.PasswordConfirmed && !c.TOTPConfirmed {
		return errors.Join(ErrInvalidConfirmation, ErrPasswordConfirmation)
	}
	if !c.SecondConfirmation {
		return errors.Join(ErrInvalidConfirmation, ErrSecondConfirmation)
	}
	return nil
}

func strictIdentity(value string) error {
	if value == "" {
		return errors.New("value is required")
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("value must not contain whitespace or invisible characters")
		}
	}
	return nil
}

func checkContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func rollbackAfterPrepare(ctx context.Context, source TemporarySource, snapshot Snapshot, receipt InvalidationReceipt, cause error) error {
	return errors.Join(cause, rollbackError(source.RestoreTemporaryState(cleanupContext(ctx), snapshot, receipt)))
}

func rollbackTransaction(ctx context.Context, tx ProductionTransaction, source TemporarySource, snapshot Snapshot, receipt InvalidationReceipt, cause error) error {
	rollbackCtx := cleanupContext(ctx)
	var rollbackErr error
	if err := tx.Rollback(rollbackCtx); err != nil {
		rollbackErr = errors.Join(rollbackErr, safeFailure(ErrRollbackFailed, "target rollback failed"))
	}
	if err := source.RestoreTemporaryState(rollbackCtx, snapshot, receipt); err != nil {
		rollbackErr = errors.Join(rollbackErr, safeFailure(ErrRollbackFailed, "temporary restore failed"))
	}
	return errors.Join(cause, rollbackError(rollbackErr))
}

func cleanupContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

func joinRollback(cause, restoreErr error) error {
	if restoreErr == nil {
		return cause
	}
	return errors.Join(cause, safeFailure(ErrRollbackFailed, "temporary restore failed"))
}

func rollbackError(err error) error {
	if err == nil {
		return nil
	}
	return safeFailure(ErrRollbackFailed, "rollback action failed")
}
