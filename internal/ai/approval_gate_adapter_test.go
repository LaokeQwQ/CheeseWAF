package ai

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
)

func TestGateActorRoleUsesCanonicalManagementRoles(t *testing.T) {
	tests := []struct {
		role string
		want approval.ActorRole
	}{
		{role: "admin", want: approval.RoleOperator},
		{role: "security_admin", want: approval.RoleSecurityAdmin},
		{role: "tenant_owner", want: approval.RoleTenantOwner},
		{role: "readonly", want: approval.RoleOperator},
		{role: "custom", want: approval.RoleOperator},
	}
	for _, test := range tests {
		if got := gateActorRole(test.role); got != test.want {
			t.Errorf("gateActorRole(%q)=%q, want %q", test.role, got, test.want)
		}
	}
}

func newTestGateApprovalAdapter(t *testing.T, store *ApprovalStore, gate *approval.Gate, epoch uint64) *GateApprovalAdapter {
	t.Helper()
	adapter, err := NewGateApprovalAdapterWithCredentialVerifier(store, gate, epoch, func(_ context.Context, _ ApprovalActor, input GateApprovalConfirmation) (GateApprovalCredentialProof, error) {
		if input.Password != "secret" {
			return GateApprovalCredentialProof{}, ErrHighRiskCredentialRejected
		}
		return NewGateApprovalCredentialProof("test-proof", true, false), nil
	})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	return adapter
}

func TestGateApprovalAdapterIgnoresCallerCredentialBooleansAndFailsClosedWithoutVerifier(t *testing.T) {
	clock := time.Date(2026, 9, 8, 14, 0, 0, 0, time.UTC)
	store := NewApprovalStore()
	gate := approval.NewGate(13)
	adapter, err := NewGateApprovalAdapter(store, gate, 13)
	if err != nil {
		t.Fatal(err)
	}
	adapter.now = func() time.Time { return clock }
	store.now = func() time.Time { return clock }
	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	approver := ApprovalActor{Subject: "approver", SessionID: "approver-session"}
	request, err := adapter.CreateFor(fakeTool{sensitivity: Destructive}, nil, "", requester)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := adapter.BeginConfirmation(request.ID, approver, "en-US")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(approval.WarningDelay)
	_, err = adapter.Confirm(request.ID, approver, GateApprovalConfirmation{PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase})
	if !errors.Is(err, ErrHighRiskCredentialVerifierUnavailable) {
		t.Fatalf("missing verifier error = %v", err)
	}
	adapter.SetCredentialVerifier(func(_ context.Context, _ ApprovalActor, input GateApprovalConfirmation) (GateApprovalCredentialProof, error) {
		if input.Password != "secret" {
			return GateApprovalCredentialProof{}, ErrHighRiskCredentialRejected
		}
		return NewGateApprovalCredentialProof("proof-13", true, false), nil
	})
	_, err = adapter.Confirm(request.ID, approver, GateApprovalConfirmation{PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase})
	if !errors.Is(err, ErrHighRiskCredentialRejected) {
		t.Fatalf("spoofed booleans were accepted: %v", err)
	}
	if got, _ := gate.Get(request.ID); got.Status != approval.StatusPending || got.Confirmation.ConfirmationID != "" {
		t.Fatalf("spoofed booleans mutated gate: %+v", got)
	}
}

func TestGateApprovalAdapterConcurrentFinalConfirmationHasSingleCommit(t *testing.T) {
	clock := time.Date(2026, 9, 8, 15, 0, 0, 0, time.UTC)
	store := NewApprovalStore()
	gate := approval.NewGate(14)
	adapter := newTestGateApprovalAdapter(t, store, gate, 14)
	adapter.now = func() time.Time { return clock }
	store.now = func() time.Time { return clock }
	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	approver := ApprovalActor{Subject: "approver", SessionID: "approver-session"}
	request, err := adapter.CreateFor(fakeTool{sensitivity: Destructive}, nil, "", requester)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := adapter.BeginConfirmation(request.ID, approver, "en-US")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(approval.WarningDelay)
	checkpointInput := GateApprovalConfirmation{Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase}
	if _, err := adapter.Confirm(request.ID, approver, checkpointInput); !errors.Is(err, approval.ErrThirdConfirmation) {
		t.Fatalf("checkpoint error = %v", err)
	}

	finalInput := checkpointInput
	finalInput.ThirdConfirmation = true
	const callers = 24
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := adapter.Confirm(request.ID, approver, finalInput)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent final confirmations yielded %d successful commits", successes)
	}
	if got, _ := gate.Get(request.ID); got.Status != approval.StatusApproved || got.Commit == nil {
		t.Fatalf("concurrent confirmation did not approve exactly once: %+v", got)
	}
}

func TestGateApprovalAdapterEnforcesServerHeldWarningLanguageAndThirdClick(t *testing.T) {
	clock := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	store := NewApprovalStore()
	gate := approval.NewGate(7)
	adapter := newTestGateApprovalAdapter(t, store, gate, 7)
	adapter.now = func() time.Time { return clock }
	store.now = func() time.Time { return clock }

	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	approver := ApprovalActor{Subject: "approver", SessionID: "approver-session", Role: "security_admin"}
	request, err := adapter.CreateForWithPreview(
		fakeTool{sensitivity: Destructive},
		map[string]any{"target": "production"},
		"before -> after",
		"before -> after",
		requester,
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	challenge, err := adapter.BeginConfirmation(request.ID, approver, "en-US")
	if err != nil {
		t.Fatalf("begin confirmation: %v", err)
	}
	if challenge.Phrase != "CONFIRM" || challenge.Language != "en-US" || challenge.ConfirmationID == "" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	clock = clock.Add(9 * time.Second)
	_, err = adapter.Confirm(request.ID, approver, GateApprovalConfirmation{
		Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase,
	})
	if !errors.Is(err, approval.ErrWarningDelay) {
		t.Fatalf("early confirmation error = %v, want warning delay", err)
	}

	clock = clock.Add(time.Second)
	checkpoint, err := adapter.Confirm(request.ID, approver, GateApprovalConfirmation{
		Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase,
	})
	if !errors.Is(err, approval.ErrThirdConfirmation) {
		t.Fatalf("checkpoint error = %v, want third confirmation", err)
	}
	if checkpoint.Commit != nil || checkpoint.Challenge.ConfirmationStep != 2 || checkpoint.Approval.Status != ApprovalPending {
		t.Fatalf("checkpoint mutated approval incorrectly: %+v", checkpoint)
	}

	final, err := adapter.Confirm(request.ID, approver, GateApprovalConfirmation{
		Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ThirdConfirmation: true, ConfirmationPhrase: challenge.Phrase,
	})
	if err != nil {
		t.Fatalf("final confirmation: %v", err)
	}
	if final.Commit == nil || final.Approval.Status != ApprovalApproved || final.Commit.SessionID != approver.SessionID || final.Commit.ConfirmationLanguage != "en-US" {
		t.Fatalf("unexpected final result: %+v", final)
	}
	if record, ok := gate.Get(request.ID); !ok || record.Confirmation.ConfirmationStep != 3 || !record.Confirmation.Local {
		t.Fatalf("gate confirmation was not local/final: %+v", record)
	}

	if _, err := adapter.BeginExecutionForWithPreview(request.ID, request.ToolName, map[string]any{"target": "production"}, "before -> after", requester); err != nil {
		t.Fatalf("begin execution: %v", err)
	}
	if _, err := adapter.MarkExecuted(request.ID, requester); err != nil {
		t.Fatalf("mark executed: %v", err)
	}
}

func TestGateApprovalAdapterBindsApproverSessionAndPhrase(t *testing.T) {
	clock := time.Date(2026, 9, 8, 11, 0, 0, 0, time.UTC)
	store := NewApprovalStore()
	gate := approval.NewGate(8)
	adapter := newTestGateApprovalAdapter(t, store, gate, 8)
	adapter.now = func() time.Time { return clock }
	store.now = func() time.Time { return clock }
	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	approver := ApprovalActor{Subject: "approver", SessionID: "approver-session"}
	request, err := adapter.CreateFor(fakeTool{sensitivity: Destructive}, nil, "", requester)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.BeginConfirmation(request.ID, requester, "zh-CN"); !errors.Is(err, ErrHighRiskApproverRequired) {
		t.Fatalf("requester self-confirmation error = %v", err)
	}
	challenge, err := adapter.BeginConfirmation(request.ID, approver, "zh-CN")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Second)
	wrongSession := approver
	wrongSession.SessionID = "other-session"
	_, err = adapter.Confirm(request.ID, wrongSession, GateApprovalConfirmation{
		Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase,
	})
	if !errors.Is(err, approval.ErrSessionChanged) {
		t.Fatalf("wrong session error = %v", err)
	}
	_, err = adapter.Confirm(request.ID, approver, GateApprovalConfirmation{
		Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: "CONFIRM",
	})
	if !errors.Is(err, approval.ErrConfirmationPhrase) {
		t.Fatalf("wrong phrase error = %v", err)
	}
}

func TestAssistantUsesGateAdapterForDestructiveToolsAndFailsClosedWithoutIt(t *testing.T) {
	registry := NewRegistry()
	registry.Register(fakeTool{sensitivity: Destructive})
	store := NewApprovalStore()
	withoutGate := NewAssistant(registry, store)
	if _, err := withoutGate.ExecuteTool(testAdminAIContext(), "fake_modify", nil, ""); err == nil || !errors.Is(err, ErrHighRiskApprovalUnavailable) {
		t.Fatalf("destructive tool without gate error = %v", err)
	}

	gate := approval.NewGate(9)
	adapter, err := NewGateApprovalAdapter(store, gate, 9)
	if err != nil {
		t.Fatal(err)
	}
	assistant := NewAssistantWithApprovalGate(registry, store, adapter)
	first, err := assistant.ExecuteTool(testAdminAIContext(), "fake_modify", nil, "")
	if err != nil {
		t.Fatalf("destructive request through adapter: %v", err)
	}
	if first.Approval == nil || first.Approval.Status != ApprovalPending {
		t.Fatalf("expected pending destructive approval, got %+v", first)
	}
}

func TestGateApprovalAdapterRejectsExpiredCommitBeforeExecution(t *testing.T) {
	clock := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := NewApprovalStore()
	store.ttl = 20 * time.Second
	gate := approval.NewGate(10)
	adapter := newTestGateApprovalAdapter(t, store, gate, 10)
	adapter.now = func() time.Time { return clock }
	store.now = func() time.Time { return clock }
	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	approver := ApprovalActor{Subject: "approver", SessionID: "approver-session"}
	request, err := adapter.CreateFor(fakeTool{sensitivity: Destructive}, nil, "", requester)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := adapter.BeginConfirmation(request.ID, approver, "en-US")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Second)
	if _, err := adapter.Confirm(request.ID, approver, GateApprovalConfirmation{Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase}); !errors.Is(err, approval.ErrThirdConfirmation) {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Second)
	if _, err := adapter.Confirm(request.ID, approver, GateApprovalConfirmation{Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ThirdConfirmation: true, ConfirmationPhrase: challenge.Phrase}); !errors.Is(err, approval.ErrExpired) {
		t.Fatalf("expired final confirmation error = %v", err)
	}
	if _, err := adapter.BeginExecutionFor(request.ID, request.ToolName, nil, requester); err == nil {
		t.Fatal("expired approval became executable")
	}
}

func TestGateApprovalAdapterReissuesFreshChallengeAfterRestart(t *testing.T) {
	store := NewApprovalStore()
	firstGate := approval.NewGate(11)
	first, err := NewGateApprovalAdapter(store, firstGate, 11)
	if err != nil {
		t.Fatal(err)
	}
	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	request, err := first.CreateFor(fakeTool{sensitivity: Destructive}, nil, "", requester)
	if err != nil {
		t.Fatal(err)
	}

	// A replacement adapter represents a process restart. The compatibility
	// store still knows the pending request, but the in-memory Gate challenge
	// and its server-held warning start are gone. A new challenge is allowed,
	// but it must start a fresh warning window and use a new confirmation ID.
	restarted, err := NewGateApprovalAdapter(store, approval.NewGate(11), 11)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := restarted.BeginConfirmation(request.ID, ApprovalActor{Subject: "approver", SessionID: "approver-session"}, "en-US")
	if err != nil {
		t.Fatalf("restarted adapter begin confirmation: %v", err)
	}
	if challenge.ConfirmationID == "" || challenge.ConfirmationID == request.ID || challenge.WarningStartedAt.IsZero() {
		t.Fatalf("restarted adapter did not issue a fresh challenge: %+v", challenge)
	}
	stored, ok := store.Get(request.ID)
	if !ok || stored.Status != ApprovalPending {
		t.Fatalf("restart changed pending request: %+v", stored)
	}
}

func TestLegacyExecutionMethodsCannotBypassGateForDestructiveApproval(t *testing.T) {
	clock := time.Date(2026, 9, 8, 13, 0, 0, 0, time.UTC)
	store := NewApprovalStore()
	store.now = func() time.Time { return clock }
	gate := approval.NewGate(12)
	adapter := newTestGateApprovalAdapter(t, store, gate, 12)
	adapter.now = func() time.Time { return clock }
	requester := ApprovalActor{Subject: "requester", SessionID: "requester-session"}
	approver := ApprovalActor{Subject: "approver", SessionID: "approver-session"}
	request, err := adapter.CreateFor(fakeTool{sensitivity: Destructive}, nil, "", requester)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := adapter.BeginConfirmation(request.ID, approver, "en-US")
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(10 * time.Second)
	if _, err := adapter.Confirm(request.ID, approver, GateApprovalConfirmation{Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ConfirmationPhrase: challenge.Phrase}); !errors.Is(err, approval.ErrThirdConfirmation) {
		t.Fatal(err)
	}
	approved, err := adapter.Confirm(request.ID, approver, GateApprovalConfirmation{Password: "secret", PasswordConfirmed: true, SecondConfirmation: true, ThirdConfirmation: true, ConfirmationPhrase: challenge.Phrase})
	if err != nil || approved.Approval.Status != ApprovalApproved {
		t.Fatalf("gate approval failed: %+v err=%v", approved, err)
	}
	if _, err := store.BeginExecutionFor(request.ID, request.ToolName, nil, requester); err == nil {
		t.Fatal("legacy BeginExecutionFor bypassed Gate")
	}
	if stored, _ := store.Get(request.ID); stored.Status != ApprovalApproved {
		t.Fatalf("legacy execution attempt changed status: %s", stored.Status)
	}
	if _, err := adapter.BeginExecutionFor(request.ID, request.ToolName, nil, requester); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkExecuted(request.ID, requester); err == nil {
		t.Fatal("legacy MarkExecuted bypassed Gate")
	}
	if stored, _ := store.Get(request.ID); stored.Status != ApprovalExecuting {
		t.Fatalf("legacy finalize attempt changed status: %s", stored.Status)
	}
	if _, err := adapter.MarkExecuted(request.ID, requester); err != nil {
		t.Fatal(err)
	}
}
