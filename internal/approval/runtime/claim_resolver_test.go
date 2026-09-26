package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

func TestApprovalClaimResolverUsesDurableRestoredApprovalMetadata(t *testing.T) {
	submittedAt := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	approvedAt := submittedAt.Add(20 * time.Second)
	request := claimResolverRequest(approvedAt.Add(time.Second))
	persistence := approval.NewMemoryPersistence()
	writer, err := approval.NewGateWithPersistence(7, persistence)
	if err != nil {
		t.Fatal(err)
	}
	record := approveCRPRequest(t, writer, request, "approval-durable", "confirmation-durable", "operator", "session-durable", "nonce-durable", submittedAt, approvedAt)
	restored, err := approval.NewGateWithPersistence(7, persistence)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(context.Background(), approvedAt.Add(time.Second), record.ID); err != nil {
		t.Fatalf("restore durable approval: %v", err)
	}

	service := &Service{gate: restored, policyEpoch: 7, clock: func() time.Time { return approvedAt.Add(2 * time.Second) }}
	resolver := service.ApprovalClaimResolver()
	if resolver == nil {
		t.Fatal("ApprovalClaimResolver() returned nil for a restored production gate")
	}
	claim, err := resolver(context.Background(), request)
	if err != nil {
		t.Fatalf("resolve approval claim: %v", err)
	}
	if claim.ApprovalID != record.ID || claim.ConfirmationID != record.Commit.ConfirmationID || claim.Actor != record.Commit.Actor || claim.Scope != record.Request.Scope || claim.PolicyEpoch != 7 || claim.IntentDigest != record.Request.IntentDigest || claim.Nonce != record.Request.Nonce || claim.SessionID != record.Request.SessionID {
		t.Fatalf("claim lost approval bindings: %+v", claim)
	}
	if !claim.IssuedAt.Equal(record.Commit.IssuedAt) || !claim.ExpiresAt.Equal(record.ExpiresAt) || claim.TTL != record.ExpiresAt.Sub(record.Commit.IssuedAt) {
		t.Fatalf("claim lifetime=%s..%s ttl=%s, want commit-to-expiry lifetime", claim.IssuedAt, claim.ExpiresAt, claim.TTL)
	}
	raw, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "totp") || strings.Contains(string(raw), "credential") {
		t.Fatalf("claim crossed credential material: %s", raw)
	}
}

func TestApprovalClaimResolverFailsClosedWhenNoRecordMatches(t *testing.T) {
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	request := claimResolverRequest(now)
	other := request
	other.Target.Key = "other-plugin"
	gate := approval.NewGate(7)
	approveCRPRequest(t, gate, other, "approval-other", "confirmation-other", "operator", "session-other", "nonce-other", now.Add(-time.Minute), now.Add(-30*time.Second))
	service := &Service{gate: gate, policyEpoch: 7, clock: func() time.Time { return now }}

	_, err := service.ApprovalClaimResolver()(context.Background(), request)
	if !errors.Is(err, ErrApprovalClaimNotFound) {
		t.Fatalf("no-match error=%v, want ErrApprovalClaimNotFound", err)
	}
}

func TestApprovalClaimResolverFailsClosedForMultipleMatches(t *testing.T) {
	now := time.Date(2026, 9, 24, 11, 0, 0, 0, time.UTC)
	request := claimResolverRequest(now)
	gate := approval.NewGate(7)
	approveCRPRequest(t, gate, request, "approval-one", "confirmation-one", "operator-one", "session-one", "nonce-one", now.Add(-50*time.Second), now.Add(-30*time.Second))
	approveCRPRequest(t, gate, request, "approval-two", "confirmation-two", "operator-two", "session-two", "nonce-two", now.Add(-50*time.Second), now.Add(-30*time.Second))
	service := &Service{gate: gate, policyEpoch: 7, clock: func() time.Time { return now }}

	_, err := service.ApprovalClaimResolver()(context.Background(), request)
	if !errors.Is(err, ErrApprovalClaimAmbiguous) {
		t.Fatalf("multiple-match error=%v, want ErrApprovalClaimAmbiguous", err)
	}
}

func TestApprovalClaimResolverRejectsExpiredApproval(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	request := claimResolverRequest(now)
	gate := approval.NewGate(7)
	approveCRPRequest(t, gate, request, "approval-expired", "confirmation-expired", "operator", "session-expired", "nonce-expired", now.Add(-2*time.Minute), now.Add(-90*time.Second))
	service := &Service{gate: gate, policyEpoch: 7, clock: func() time.Time { return now }}

	_, err := service.ApprovalClaimResolver()(context.Background(), request)
	if !errors.Is(err, ErrApprovalClaimExpired) {
		t.Fatalf("expired error=%v, want ErrApprovalClaimExpired", err)
	}
}

func TestApprovalClaimResolverRejectsBindingDrift(t *testing.T) {
	now := time.Date(2026, 9, 24, 13, 0, 0, 0, time.UTC)
	request := claimResolverRequest(now)
	gate := approval.NewGate(7)
	approved := approveCRPRequest(t, gate, request, "approval-drift", "confirmation-drift", "operator", "session-drift", "nonce-drift", now.Add(-time.Minute), now.Add(-30*time.Second))

	tests := []struct {
		name   string
		mutate func(*approval.Record)
	}{
		{name: "intent", mutate: func(record *approval.Record) { record.Commit.IntentDigest = strings.Repeat("f", 64) }},
		{name: "scope", mutate: func(record *approval.Record) { record.Commit.Scope = "crp:promote:other" }},
		{name: "epoch", mutate: func(record *approval.Record) { record.Commit.PolicyEpoch++ }},
		{name: "session", mutate: func(record *approval.Record) { record.Confirmation.SessionID = "session-other" }},
		{name: "nonce", mutate: func(record *approval.Record) { record.Confirmation.Nonce = "nonce-other" }},
		{name: "confirmation actor", mutate: func(record *approval.Record) { record.Confirmation.Actor = "operator-other" }},
		{name: "confirmation id", mutate: func(record *approval.Record) { record.Confirmation.ConfirmationID = "confirmation-other" }},
		{name: "ttl", mutate: func(record *approval.Record) { record.Commit.TTL += time.Second }},
		{name: "expiry", mutate: func(record *approval.Record) { record.Commit.ExpiresAt = record.Commit.ExpiresAt.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := approved
			commit := *approved.Commit
			record.Commit = &commit
			test.mutate(&record)
			_, err := resolveApprovalClaim([]approval.Record{record}, 7, now, request)
			if !errors.Is(err, ErrApprovalClaimInvalid) {
				t.Fatalf("binding drift error=%v, want ErrApprovalClaimInvalid", err)
			}
		})
	}
}

func TestApprovalClaimResolverDoesNotMatchOperationOrEpochDrift(t *testing.T) {
	now := time.Date(2026, 9, 24, 13, 30, 0, 0, time.UTC)
	request := claimResolverRequest(now)
	gate := approval.NewGate(7)
	approved := approveCRPRequest(t, gate, request, "approval-operation-drift", "confirmation-operation-drift", "operator", "session-operation-drift", "nonce-operation-drift", now.Add(-50*time.Second), now.Add(-30*time.Second))

	tests := []struct {
		name   string
		mutate func(*approval.Record)
	}{
		{name: "intent", mutate: func(record *approval.Record) {
			digest := strings.Repeat("f", 64)
			record.Request.IntentDigest = digest
			record.Confirmation.IntentDigest = digest
			record.Commit.IntentDigest = digest
		}},
		{name: "scope", mutate: func(record *approval.Record) {
			scope := "crp:promote:other-plugin"
			record.Request.Scope = scope
			record.Confirmation.Scope = scope
			record.Commit.Scope = scope
		}},
		{name: "epoch", mutate: func(record *approval.Record) {
			record.Request.PolicyEpoch++
			record.Confirmation.PolicyEpoch++
			record.Commit.PolicyEpoch++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := approved
			commit := *approved.Commit
			record.Commit = &commit
			test.mutate(&record)
			_, err := resolveApprovalClaim([]approval.Record{record}, 7, now, request)
			if !errors.Is(err, ErrApprovalClaimNotFound) {
				t.Fatalf("operation drift error=%v, want ErrApprovalClaimNotFound", err)
			}
		})
	}
}

func TestApprovalClaimResolverRejectsGateEpochDrift(t *testing.T) {
	now := time.Date(2026, 9, 24, 14, 0, 0, 0, time.UTC)
	request := claimResolverRequest(now)
	gate := approval.NewGate(7)
	approveCRPRequest(t, gate, request, "approval-epoch", "confirmation-epoch", "operator", "session-epoch", "nonce-epoch", now.Add(-time.Minute), now.Add(-30*time.Second))
	if err := gate.AdvanceEpoch(8); err != nil {
		t.Fatal(err)
	}
	service := &Service{gate: gate, policyEpoch: 7, clock: func() time.Time { return now }}

	_, err := service.ApprovalClaimResolver()(context.Background(), request)
	if !errors.Is(err, ErrApprovalClaimInvalid) {
		t.Fatalf("gate epoch drift error=%v, want ErrApprovalClaimInvalid", err)
	}
}

func claimResolverRequest(requestedAt time.Time) activation.AuthorizationRequest {
	return activation.AuthorizationRequest{
		Action:           crp.RuntimeActionPromote,
		Target:           activation.RuntimeTarget{Key: "plugin-one", Revision: 4, ManifestIdentity: strings.Repeat("a", 64)},
		ExpectedRevision: 4,
		RequestedAt:      requestedAt,
	}
}

func approveCRPRequest(t *testing.T, gate *approval.Gate, request activation.AuthorizationRequest, approvalID, confirmationID, actor, sessionID, nonce string, submittedAt, approvedAt time.Time) approval.Record {
	t.Helper()
	record, err := gate.Submit(submittedAt, approval.Request{
		ID:                   approvalID,
		Risk:                 approval.RiskMedium,
		Scope:                activation.ApprovalScope(request),
		PolicyEpoch:          7,
		TTL:                  time.Minute,
		Actor:                actor,
		SessionID:            sessionID,
		ConfirmationLanguage: "zh-CN",
		IntentDigest:         activation.ApprovalIntentDigest(request),
		Nonce:                nonce,
	})
	if err != nil {
		t.Fatalf("submit approval: %v", err)
	}
	phrase, err := approval.ExpectedConfirmationPhrase(record.Request.ConfirmationLanguage)
	if err != nil {
		t.Fatal(err)
	}
	_, err = gate.Confirm(approvedAt, record.ID, approval.Confirmation{
		WarningReadAt:        approvedAt.Add(-approval.WarningDelay),
		PasswordConfirmed:    true,
		SecondConfirmation:   true,
		ConfirmationID:       confirmationID,
		Actor:                actor,
		Scope:                record.Request.Scope,
		PolicyEpoch:          record.Request.PolicyEpoch,
		Local:                true,
		SessionID:            record.Request.SessionID,
		ConfirmationLanguage: record.Request.ConfirmationLanguage,
		ConfirmationPhrase:   phrase,
		IntentDigest:         record.Request.IntentDigest,
		Nonce:                record.Request.Nonce,
	})
	if err != nil {
		t.Fatalf("confirm approval: %v", err)
	}
	approved, ok := gate.Get(record.ID)
	if !ok {
		t.Fatalf("approved record %q not found", record.ID)
	}
	return approved
}
