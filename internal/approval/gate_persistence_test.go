package approval

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type failingApprovalPersistence struct {
	*MemoryPersistence
	err error
}

type partialApprovalPersistence struct {
	*MemoryPersistence
	applyCount int
	failOnce   bool
}

type epochTrackingPersistence struct {
	*MemoryPersistence
	epoch  uint64
	casErr error
}

type epochGuardedApprovalPersistence struct {
	*MemoryPersistence
	mu    sync.Mutex
	epoch uint64
}

type snapshotApprovalPersistence struct {
	backing       *MemoryPersistence
	policyEpoch   uint64
	policyCalls   int
	loadCalls     int
	eventsCalls   int
	snapshotCalls int
}

type epochSnapshotApprovalPersistence struct {
	backing            *MemoryPersistence
	loadCalls          int
	eventsCalls        int
	snapshotCalls      int
	epochSnapshotCalls int
	policyEpochCalls   int
}

type legacyApprovalPersistence struct {
	backing     *MemoryPersistence
	loadCalls   int
	eventsCalls int
}

func (p *legacyApprovalPersistence) Apply(ctx context.Context, m ApprovalMutation) error {
	return p.backing.Apply(ctx, m)
}

func (p *snapshotApprovalPersistence) Load(ctx context.Context, id string) (Record, error) {
	p.loadCalls++
	return Record{}, errors.New("legacy Load should not be called")
}

func (p *snapshotApprovalPersistence) Events(ctx context.Context, id string) ([]AuditEvent, error) {
	p.eventsCalls++
	return nil, errors.New("legacy Events should not be called")
}

func (p *snapshotApprovalPersistence) LoadWithEvents(ctx context.Context, id string) (Record, []AuditEvent, error) {
	p.snapshotCalls++
	return p.backing.LoadWithEvents(ctx, id)
}

func (p *snapshotApprovalPersistence) Apply(ctx context.Context, m ApprovalMutation) error {
	return p.backing.Apply(ctx, m)
}

func (p *snapshotApprovalPersistence) PolicyEpoch(context.Context) (uint64, error) {
	p.policyCalls++
	return p.policyEpoch, nil
}

func (p *epochSnapshotApprovalPersistence) Apply(ctx context.Context, m ApprovalMutation) error {
	return p.backing.Apply(ctx, m)
}

func (p *epochSnapshotApprovalPersistence) Load(ctx context.Context, id string) (Record, error) {
	p.loadCalls++
	return Record{}, errors.New("legacy Load should not be called")
}

func (p *epochSnapshotApprovalPersistence) Events(ctx context.Context, id string) ([]AuditEvent, error) {
	p.eventsCalls++
	return nil, errors.New("legacy Events should not be called")
}

func (p *epochSnapshotApprovalPersistence) LoadWithEvents(ctx context.Context, id string) (Record, []AuditEvent, error) {
	p.snapshotCalls++
	return Record{}, nil, errors.New("legacy snapshot should not be called")
}

func (p *epochSnapshotApprovalPersistence) LoadWithEventsAtEpoch(ctx context.Context, id string, expectedEpoch uint64) (Record, []AuditEvent, error) {
	p.epochSnapshotCalls++
	return p.backing.LoadWithEventsAtEpoch(ctx, id, expectedEpoch)
}

func (p *epochSnapshotApprovalPersistence) PolicyEpoch(context.Context) (uint64, error) {
	p.policyEpochCalls++
	return 0, errors.New("standalone epoch read should not be called")
}

func (p *legacyApprovalPersistence) Load(ctx context.Context, id string) (Record, error) {
	p.loadCalls++
	return p.backing.Load(ctx, id)
}

func (p *legacyApprovalPersistence) Events(ctx context.Context, id string) ([]AuditEvent, error) {
	p.eventsCalls++
	return p.backing.Events(ctx, id)
}

func (p *epochTrackingPersistence) CompareAndSetEpoch(_ context.Context, expected, next uint64) error {
	if p.casErr != nil {
		return p.casErr
	}
	if next < expected {
		return ErrEpochRegression
	}
	if p.epoch != expected {
		return ErrEpochChanged
	}
	p.epoch = next
	return nil
}

func (p *epochGuardedApprovalPersistence) ApplyAtEpoch(ctx context.Context, expected uint64, m ApprovalMutation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.epoch != expected || m.Record.Request.PolicyEpoch != expected || m.Event.PolicyEpoch != expected {
		return ErrEpochChanged
	}
	return p.MemoryPersistence.Apply(ctx, m)
}

func (p *epochGuardedApprovalPersistence) ApplyBatchAtEpoch(ctx context.Context, expected uint64, ms []ApprovalMutation) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.epoch != expected {
		return ErrEpochChanged
	}
	for _, m := range ms {
		if m.Record.Request.PolicyEpoch != expected || m.Event.PolicyEpoch != expected {
			return ErrEpochChanged
		}
	}
	return p.MemoryPersistence.ApplyBatch(ctx, ms)
}

func (p *epochGuardedApprovalPersistence) CompareAndSetEpoch(_ context.Context, expected, next uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if next < expected {
		return ErrEpochRegression
	}
	if p.epoch != expected {
		return ErrEpochChanged
	}
	p.epoch = next
	return nil
}

func (p *partialApprovalPersistence) Apply(ctx context.Context, m ApprovalMutation) error {
	p.applyCount++
	if p.failOnce && p.applyCount == 2 {
		p.failOnce = false
		return errors.New("second write failed")
	}
	return p.MemoryPersistence.Apply(ctx, m)
}
func (p *partialApprovalPersistence) ApplyBatch(ctx context.Context, ms []ApprovalMutation) error {
	for _, m := range ms {
		if err := p.Apply(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func (p failingApprovalPersistence) Apply(context.Context, ApprovalMutation) error { return p.err }

func TestGatePersistenceFailureDoesNotExposeSubmittedRequest(t *testing.T) {
	p := failingApprovalPersistence{MemoryPersistence: NewMemoryPersistence(), err: errors.New("storage unavailable")}
	g, err := NewGateWithPersistence(7, p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = g.Submit(time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC), Request{ID: "durable-fail", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN"})
	if !errors.Is(err, p.err) {
		t.Fatalf("Submit() error = %v, want persistence error", err)
	}
	if _, ok := g.Get("durable-fail"); ok {
		t.Fatal("failed durable submit became visible in memory")
	}
}

func TestGateRestoresRecordAndReplayLedgerFromPersistence(t *testing.T) {
	p := NewMemoryPersistence()
	g, err := NewGateWithPersistence(7, p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	record, err := g.Submit(now, Request{ID: "durable-restore", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Confirm(now.Add(WarningDelay), record.ID, approvalTestBinding(record, now.Add(WarningDelay), "confirm-restore", "operator")); err != nil {
		t.Fatal(err)
	}
	restored, err := NewGateWithPersistence(7, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreRecord(context.Background(), now, record.ID); err != nil {
		t.Fatal(err)
	}
	got, ok := restored.Get(record.ID)
	if !ok || got.Status != StatusApproved || got.Commit == nil {
		t.Fatalf("restored record = %+v, ok=%v", got, ok)
	}
	if _, err := restored.Confirm(now, record.ID, approvalTestBinding(got, now, "confirm-restore", "operator")); !errors.Is(err, ErrNotPending) {
		t.Fatalf("restored confirmation replay/status error = %v", err)
	}
}

func TestGateRestoreRecordPrefersConsistentSnapshotPersistence(t *testing.T) {
	backing := NewMemoryPersistence()
	writer, err := NewGateWithPersistence(7, backing)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	record, err := writer.Submit(now, Request{ID: "snapshot-restore", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}

	persistence := &snapshotApprovalPersistence{backing: backing, policyEpoch: 7}
	restored, err := NewGateWithPersistence(7, persistence)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreRecord(context.Background(), now, record.ID); err != nil {
		t.Fatalf("RestoreRecord: %v", err)
	}
	if persistence.policyCalls != 1 || persistence.snapshotCalls != 1 || persistence.loadCalls != 0 || persistence.eventsCalls != 0 {
		t.Fatalf("restore read path = policy:%d snapshot:%d load:%d events:%d", persistence.policyCalls, persistence.snapshotCalls, persistence.loadCalls, persistence.eventsCalls)
	}
}

func TestGateRestoreRecordPrefersEpochSnapshotAndRejectsMismatch(t *testing.T) {
	backing := NewMemoryPersistence()
	writer, err := NewGateWithPersistence(7, backing)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	record, err := writer.Submit(now, Request{ID: "epoch-snapshot-restore", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}

	persistence := &epochSnapshotApprovalPersistence{backing: backing}
	restored, err := NewGateWithPersistence(7, persistence)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreRecord(context.Background(), now, record.ID); err != nil {
		t.Fatalf("RestoreRecord: %v", err)
	}
	if persistence.epochSnapshotCalls != 1 || persistence.policyEpochCalls != 0 || persistence.snapshotCalls != 0 || persistence.loadCalls != 0 || persistence.eventsCalls != 0 {
		t.Fatalf("restore read path = epoch:%d policy:%d snapshot:%d load:%d events:%d", persistence.epochSnapshotCalls, persistence.policyEpochCalls, persistence.snapshotCalls, persistence.loadCalls, persistence.eventsCalls)
	}

	if _, _, err := backing.LoadWithEventsAtEpoch(context.Background(), record.ID, 8); !errors.Is(err, ErrEpochChanged) {
		t.Fatalf("epoch mismatch error = %v, want ErrEpochChanged", err)
	}
}

func TestGateRestoreRecordRetainsLegacyPersistenceFallback(t *testing.T) {
	backing := NewMemoryPersistence()
	writer, err := NewGateWithPersistence(7, backing)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	record, err := writer.Submit(now, Request{ID: "legacy-restore", Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}

	persistence := &legacyApprovalPersistence{backing: backing}
	restored, err := NewGateWithPersistence(7, persistence)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreRecord(context.Background(), now, record.ID); err != nil {
		t.Fatalf("RestoreRecord: %v", err)
	}
	if persistence.loadCalls != 1 || persistence.eventsCalls != 1 {
		t.Fatalf("legacy restore read path = load:%d events:%d", persistence.loadCalls, persistence.eventsCalls)
	}
}

func TestGateRetriesAfterPartialPersistenceWithoutExposingMemoryState(t *testing.T) {
	p := &partialApprovalPersistence{MemoryPersistence: NewMemoryPersistence(), failOnce: true}
	g, err := NewGateWithPersistence(7, p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	req := Request{ID: "partial-retry", Risk: RiskLow, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, PreApproved: true, Actor: "scheduler", SessionID: "session-a", ConfirmationLanguage: "zh-CN"}
	if _, err := g.Submit(now, req); err == nil {
		t.Fatal("expected partial persistence failure")
	}
	if _, ok := g.Get(req.ID); ok {
		t.Fatal("partial failure exposed in-memory record")
	}
	if _, err := g.Submit(now, req); err != nil {
		t.Fatalf("retry submit: %v", err)
	}
	if got, ok := g.Get(req.ID); !ok || got.Status != StatusApproved {
		t.Fatalf("retry did not restore approved state: %+v %v", got, ok)
	}
}

func TestGateAdvanceEpochKeepsMemoryAndPersistenceConsistent(t *testing.T) {
	p := &epochTrackingPersistence{MemoryPersistence: NewMemoryPersistence(), epoch: 7}
	g, err := NewGateWithPersistence(7, p)
	if err != nil {
		t.Fatal(err)
	}

	if err := g.AdvanceEpoch(8); err != nil {
		t.Fatalf("AdvanceEpoch(8): %v", err)
	}
	if g.policyEpoch != 8 || p.epoch != 8 {
		t.Fatalf("successful advance diverged: memory=%d persistence=%d", g.policyEpoch, p.epoch)
	}

	if err := g.AdvanceEpoch(7); !errors.Is(err, ErrEpochRegression) {
		t.Fatalf("AdvanceEpoch(7) error=%v, want epoch regression", err)
	}
	if g.policyEpoch != 8 || p.epoch != 8 {
		t.Fatalf("rollback changed epoch: memory=%d persistence=%d", g.policyEpoch, p.epoch)
	}

	p.casErr = ErrEpochChanged
	if err := g.AdvanceEpoch(9); !errors.Is(err, ErrEpochChanged) {
		t.Fatalf("CAS mismatch error=%v, want epoch changed", err)
	}
	if g.policyEpoch != 8 || p.epoch != 8 {
		t.Fatalf("failed CAS changed epoch: memory=%d persistence=%d", g.policyEpoch, p.epoch)
	}
}

func TestGatePersistentMutationsFailClosedAfterExternalEpochAdvance(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		op   string
	}{
		{name: "submit", op: "submit"},
		{name: "confirm", op: "confirm"},
		{name: "checkpoint", op: "checkpoint"},
		{name: "revoke", op: "revoke"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &epochGuardedApprovalPersistence{MemoryPersistence: NewMemoryPersistence(), epoch: 7}
			g, err := NewGateWithPersistence(7, p)
			if err != nil {
				t.Fatal(err)
			}
			req := Request{ID: "epoch-fence-" + tt.op, Risk: RiskMedium, Scope: "site:a", PolicyEpoch: 7, TTL: time.Minute, Actor: "operator", SessionID: "session-a", ConfirmationLanguage: "zh-CN"}
			if tt.op == "submit" {
				req.Risk = RiskLow
				req.PreApproved = true
				req.Actor = "scheduler"
			}
			if tt.op == "checkpoint" {
				req.Risk = RiskHigh
			}
			var record Record
			if tt.op != "submit" {
				record, err = g.Submit(now, req)
				if err != nil {
					t.Fatalf("initial Submit: %v", err)
				}
			}
			if err := p.CompareAndSetEpoch(context.Background(), 7, 8); err != nil {
				t.Fatalf("external epoch advance: %v", err)
			}

			switch tt.op {
			case "submit":
				_, err = g.Submit(now, req)
			case "confirm", "checkpoint":
				_, err = g.Confirm(now.Add(WarningDelay), record.ID, approvalTestBinding(record, now.Add(WarningDelay), "confirm-drift", "operator"))
			case "revoke":
				err = g.Revoke(now, record.ID, "operator", "epoch drift")
			}
			if !errors.Is(err, ErrEpochChanged) {
				t.Fatalf("%s after durable epoch advance error = %v, want ErrEpochChanged", tt.op, err)
			}

			if tt.op == "submit" {
				if _, ok := g.Get(req.ID); ok {
					t.Fatal("failed durable submit left an in-memory record")
				}
				if _, err := p.Events(context.Background(), req.ID); !errors.Is(err, ErrApprovalNotFound) {
					t.Fatalf("failed durable submit events error = %v, want ErrApprovalNotFound", err)
				}
				return
			}

			events, err := p.Events(context.Background(), record.ID)
			if err != nil {
				t.Fatalf("Events after rejected %s: %v", tt.op, err)
			}
			if len(events) != 1 {
				t.Fatalf("rejected %s left %d durable events, want 1", tt.op, len(events))
			}
			got, ok := g.Get(record.ID)
			if !ok || got.Status != StatusPending || got.Confirmation.ConfirmationID != "" {
				t.Fatalf("rejected %s did not restore pending memory state: %+v ok=%v", tt.op, got, ok)
			}
		})
	}
}

func TestGuardedPersistenceRejectsIdempotentReplayAfterEpochDrift(t *testing.T) {
	p := &epochGuardedApprovalPersistence{MemoryPersistence: NewMemoryPersistence(), epoch: 7}
	m := approvalMutationFixture()
	if err := p.ApplyAtEpoch(context.Background(), 7, m); err != nil {
		t.Fatalf("initial guarded mutation: %v", err)
	}
	if err := p.CompareAndSetEpoch(context.Background(), 7, 8); err != nil {
		t.Fatalf("external epoch advance: %v", err)
	}
	if err := p.ApplyAtEpoch(context.Background(), 7, m); !errors.Is(err, ErrEpochChanged) {
		t.Fatalf("stale idempotent replay error = %v, want ErrEpochChanged", err)
	}
	events, err := p.Events(context.Background(), m.Record.ID)
	if err != nil || len(events) != 1 {
		t.Fatalf("stale idempotent replay changed durable events: events=%d err=%v", len(events), err)
	}
}
