package migration

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	mu          sync.Mutex
	profile     string
	state       Snapshot
	invalidated bool
	restored    bool
	receipt     InvalidationReceipt
	steps       []string
	errProfile  error
	errSnapshot error
	errInvalid  error
	errRestore  error
}

func (s *fakeSource) Profile(context.Context) (string, error) {
	if s.errProfile != nil {
		return "", s.errProfile
	}
	return s.profile, nil
}
func (s *fakeSource) Snapshot(context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, "snapshot")
	if s.errSnapshot != nil {
		return Snapshot{}, s.errSnapshot
	}
	return s.state, nil
}
func (s *fakeSource) InvalidateTemporaryState(context.Context) (InvalidationReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, "invalidate")
	if s.errInvalid != nil {
		return InvalidationReceipt{}, s.errInvalid
	}
	s.invalidated = true
	return s.receipt, nil
}
func (s *fakeSource) RestoreTemporaryState(context.Context, Snapshot, InvalidationReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, "restore")
	if s.errRestore != nil {
		return s.errRestore
	}
	s.restored = true
	s.invalidated = false
	return nil
}

type fakePrerequisite struct {
	err   error
	calls int
}

func (p *fakePrerequisite) Check(context.Context) error { p.calls++; return p.err }

type fakeTransaction struct {
	source                               *fakeSource
	errManagement, errMigrate, errRotate error
	errCommit, errRollback               error
	steps                                []string
}

func (t *fakeTransaction) MigrateManagementState(context.Context, Snapshot) error {
	t.steps = append(t.steps, "migrate_management")
	return t.errManagement
}
func (t *fakeTransaction) MigrateTokenMetadata(context.Context, Snapshot) error {
	t.steps = append(t.steps, "migrate_tokens")
	return t.errMigrate
}
func (t *fakeTransaction) RotateTokenMetadata(context.Context, Snapshot) error {
	t.steps = append(t.steps, "rotate_tokens")
	return t.errRotate
}
func (t *fakeTransaction) Commit(context.Context) error {
	t.steps = append(t.steps, "commit")
	return t.errCommit
}
func (t *fakeTransaction) Rollback(context.Context) error {
	t.steps = append(t.steps, "rollback")
	return t.errRollback
}

type fakeTarget struct {
	tx         *fakeTransaction
	beginErr   error
	beginCalls int
}

func (t *fakeTarget) Begin(context.Context, Snapshot) (ProductionTransaction, error) {
	t.beginCalls++
	if t.beginErr != nil {
		return nil, t.beginErr
	}
	return t.tx, nil
}

type fakeConfirmer struct {
	calls int
	err   error
}

func (c *fakeConfirmer) Confirm(context.Context, ConfirmationRequest) error { c.calls++; return c.err }

func migrationFixture() (Options, *fakeSource, *fakeTarget, *fakeConfirmer, *fakePrerequisite, *fakePrerequisite, *fakePrerequisite) {
	source := &fakeSource{profile: TemporaryProfile, state: Snapshot{ID: "temporary-state", TokenMetadata: []byte("token-meta")}, receipt: InvalidationReceipt{Sessions: true, Setup: true, Join: true, CAPTCHA: true, Locks: true}}
	tx := &fakeTransaction{source: source}
	target := &fakeTarget{tx: tx}
	confirm := &fakeConfirmer{}
	pg, raft, redis := &fakePrerequisite{}, &fakePrerequisite{}, &fakePrerequisite{}
	now := time.Date(2026, 9, 8, 12, 0, 20, 0, time.UTC)
	return Options{Source: source, Target: target, PostgreSQL: pg, NativeRaft: raft, Redis: redis, Confirmer: confirm, Now: func() time.Time { return now }}, source, target, confirm, pg, raft, redis
}

func validConfirmation(now time.Time) ConfirmationRequest {
	return ConfirmationRequest{Actor: "operator", SessionID: "session-a", Language: "en-US", Phrase: "CONFIRM", WarningReadAt: now.Add(-WarningDelay), PasswordConfirmed: true, SecondConfirmation: true, ConfirmationID: "confirm-1", Local: true}
}

func TestRunRequiresSecondConfirmationAndExactLanguagePhrase(t *testing.T) {
	opts, source, _, confirmer, _, _, _ := migrationFixture()
	now := opts.Now()
	for name, mutate := range map[string]func(*ConfirmationRequest){
		"missing second confirmation": func(c *ConfirmationRequest) { c.SecondConfirmation = false },
		"wrong phrase":                func(c *ConfirmationRequest) { c.Phrase = "confirm" },
		"wrong language":              func(c *ConfirmationRequest) { c.Language, c.Phrase = "zh-CN", "CONFIRM" },
		"warning too short":           func(c *ConfirmationRequest) { c.WarningReadAt = now.Add(-WarningDelay + time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			req := validConfirmation(now)
			mutate(&req)
			_, err := New(opts).Run(context.Background(), req)
			if err == nil {
				t.Fatal("invalid confirmation unexpectedly accepted")
			}
			if source.invalidated {
				t.Fatal("confirmation failure mutated temporary state")
			}
			if confirmer.calls != 0 {
				t.Fatal("confirmation adapter called after local validation failure")
			}
		})
	}
}

func TestRunFailsClosedWhenProductionPrerequisiteIsMissingOrUnhealthy(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"missing postgres": func(o *Options) { o.PostgreSQL = nil },
		"missing raft":     func(o *Options) { o.NativeRaft = nil },
		"missing redis":    func(o *Options) { o.Redis = nil },
		"postgres error":   func(o *Options) { o.PostgreSQL = &fakePrerequisite{err: errors.New("pg down")} },
		"raft error":       func(o *Options) { o.NativeRaft = &fakePrerequisite{err: errors.New("raft down")} },
		"redis error":      func(o *Options) { o.Redis = &fakePrerequisite{err: errors.New("redis down")} },
	} {
		t.Run(name, func(t *testing.T) {
			opts, source, _, _, _, _, _ := migrationFixture()
			mutate(&opts)
			_, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
			if !errors.Is(err, ErrPrerequisiteUnavailable) {
				t.Fatalf("error=%v, want prerequisite failure", err)
			}
			if source.invalidated {
				t.Fatal("prerequisite failure invalidated temporary state")
			}
		})
	}
}

func TestRunInvalidatesAllTemporaryStateAndRotatesAfterMetadataMigration(t *testing.T) {
	opts, source, target, confirmer, _, _, _ := migrationFixture()
	result, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !result.Committed || !result.ManagementStateMigrated || !result.TokenMetadataMigrated || !result.TokensRotated || !result.TemporaryInvalidated {
		t.Fatalf("incomplete result: %+v", result)
	}
	if !source.invalidated || target.beginCalls != 1 || confirmer.calls != 1 {
		t.Fatalf("unexpected state: invalidated=%v begin=%d confirmations=%d", source.invalidated, target.beginCalls, confirmer.calls)
	}
	want := []string{"snapshot", "invalidate"}
	if !reflect.DeepEqual(source.steps, want) {
		t.Fatalf("source steps=%v want=%v", source.steps, want)
	}
	if got, want := target.tx.steps, []string{"migrate_management", "migrate_tokens", "rotate_tokens", "commit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction steps=%v want=%v", got, want)
	}
}

func TestRunRollsBackAndRestoresTemporaryStateWhenTokenRotationFails(t *testing.T) {
	opts, source, target, _, _, _, _ := migrationFixture()
	target.tx.errRotate = errors.New("rotation failed")
	_, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if err == nil || !errors.Is(err, ErrTokenMetadataRotation) {
		t.Fatalf("error=%v, want rotation failure", err)
	}
	if !source.restored || source.invalidated {
		t.Fatalf("temporary state was not restored: restored=%v invalidated=%v", source.restored, source.invalidated)
	}
	if got, want := target.tx.steps, []string{"migrate_management", "migrate_tokens", "rotate_tokens", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction steps=%v want=%v", got, want)
	}
}

func TestRunRollsBackWhenCompleteManagementTargetDoesNotMigrateTokenMetadata(t *testing.T) {
	opts, source, target, _, _, _, _ := migrationFixture()
	target.tx.errMigrate = errors.New("token metadata unavailable")
	result, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if !errors.Is(err, ErrTokenMetadataMigration) {
		t.Fatalf("token metadata migration error=%v", err)
	}
	if result.TokenMetadataMigrated || !source.restored || source.invalidated {
		t.Fatalf("false migration evidence or missing rollback: result=%+v restored=%t invalidated=%t", result, source.restored, source.invalidated)
	}
	if got, want := target.tx.steps, []string{"migrate_management", "migrate_tokens", "rollback"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("transaction steps=%v want=%v", got, want)
	}
}

func TestRunRollsBackAndRestoresTemporaryStateWhenCommitFails(t *testing.T) {
	opts, source, target, _, _, _, _ := migrationFixture()
	target.tx.errCommit = errors.New("commit failed")
	_, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if err == nil || !errors.Is(err, ErrCommitFailed) {
		t.Fatalf("error=%v, want commit failure", err)
	}
	if !source.restored || source.invalidated {
		t.Fatalf("temporary state was not restored: restored=%v invalidated=%v", source.restored, source.invalidated)
	}
}

func TestRunDoesNotRestoreTemporaryStateWhenCommitOutcomeIsUnknown(t *testing.T) {
	opts, source, target, _, _, _, _ := migrationFixture()
	target.tx.errCommit = errors.Join(ErrCommitOutcomeUnknown, errors.New("connection lost after commit request"))
	result, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if !errors.Is(err, ErrCommitOutcomeUnknown) || !errors.Is(err, ErrCommitFailed) {
		t.Fatalf("error=%v, want unknown commit outcome", err)
	}
	if source.restored || !source.invalidated {
		t.Fatalf("unknown commit outcome restored temporary state: restored=%v invalidated=%v", source.restored, source.invalidated)
	}
	if result.SnapshotID == "" || !result.TemporaryInvalidated || !result.TokensRotated || result.Committed {
		t.Fatalf("result lost pre-commit evidence: %+v", result)
	}
}

func TestRunRestoresTemporaryStateWhenTargetCannotBegin(t *testing.T) {
	opts, source, target, _, _, _, _ := migrationFixture()
	target.beginErr = errors.New("target unavailable")
	_, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if err == nil || !errors.Is(err, ErrTransactionUnavailable) {
		t.Fatalf("error=%v, want target failure", err)
	}
	if !source.restored || source.invalidated {
		t.Fatalf("temporary state was not restored: restored=%v invalidated=%v", source.restored, source.invalidated)
	}
}

func TestRunRejectsIncompleteInvalidationReceipt(t *testing.T) {
	opts, source, target, _, _, _, _ := migrationFixture()
	source.receipt.Locks = false
	_, err := New(opts).Run(context.Background(), validConfirmation(opts.Now()))
	if !errors.Is(err, ErrTemporaryInvalidationIncomplete) {
		t.Fatalf("error=%v, want incomplete invalidation", err)
	}
	if target.beginCalls != 0 || source.invalidated {
		t.Fatalf("incomplete invalidation advanced migration: begin=%d invalidated=%v", target.beginCalls, source.invalidated)
	}
}

func TestRunRejectsWhitespaceIdentityWithoutCallingConfirmation(t *testing.T) {
	opts, _, _, confirmer, _, _, _ := migrationFixture()
	req := validConfirmation(opts.Now())
	req.Actor = " operator"
	if _, err := New(opts).Run(context.Background(), req); !errors.Is(err, ErrInvalidConfirmation) {
		t.Fatalf("error=%v, want invalid confirmation", err)
	}
	if confirmer.calls != 0 {
		t.Fatal("invalid identity reached confirmation adapter")
	}
}
