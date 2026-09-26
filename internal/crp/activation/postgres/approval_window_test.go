package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

func TestValidateApprovalInteractiveWindow(t *testing.T) {
	record, request := delayedApprovalWindow(t)
	if record.Request.TTL != 2*time.Minute || record.Commit.TTL != record.Request.TTL || request.ApprovalClaim.TTL != 2*time.Minute-approval.WarningDelay {
		t.Fatal("fixture did not preserve the original TTL and delayed authorization window")
	}
	if err := validateApproval(record, request); err != nil {
		t.Fatalf("valid delayed approval rejected: %v", err)
	}
}

func TestValidateApprovalRejectsMismatchedLedgerRequestID(t *testing.T) {
	record, request := delayedApprovalWindow(t)
	record.Request.ID = "different-approval-window"

	if err := validateApproval(record, request); !errors.Is(err, activation.ErrAuthorizationDenied) {
		t.Fatalf("mismatched ledger request ID error=%v, want authorization denied", err)
	}
}

func TestValidateApprovalRejectsLedgerExpiryDrift(t *testing.T) {
	record, request := delayedApprovalWindow(t)
	record.ExpiresAt = record.ExpiresAt.Add(-time.Second)
	record.Commit.ExpiresAt = record.ExpiresAt
	request.ApprovalClaim.ExpiresAt = record.ExpiresAt
	request.ApprovalClaim.TTL = record.Commit.ExpiresAt.Sub(record.Commit.IssuedAt)

	if err := validateApproval(record, request); !errors.Is(err, activation.ErrAuthorizationDenied) {
		t.Fatalf("ledger expiry drift error=%v, want authorization denied", err)
	}
}

func TestValidateApprovalRejectsWindowTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*approval.Record, *activation.ApprovalClaim)
	}{
		{"original TTL as effective TTL", func(r *approval.Record, c *activation.ApprovalClaim) { c.TTL = r.Request.TTL }},
		{"shifted window", func(_ *approval.Record, c *activation.ApprovalClaim) {
			c.IssuedAt = c.IssuedAt.Add(time.Second)
			c.ExpiresAt = c.ExpiresAt.Add(time.Second)
		}},
		{"extended expiry", func(_ *approval.Record, c *activation.ApprovalClaim) {
			c.ExpiresAt = c.ExpiresAt.Add(time.Second)
			c.TTL += time.Second
		}},
		{"earlier issue", func(_ *approval.Record, c *activation.ApprovalClaim) {
			c.IssuedAt = c.IssuedAt.Add(-time.Second)
			c.TTL += time.Second
		}},
		{"shortened expiry", func(_ *approval.Record, c *activation.ApprovalClaim) {
			c.ExpiresAt = c.ExpiresAt.Add(-time.Second)
			c.TTL -= time.Second
		}},
		{"commit TTL drift", func(r *approval.Record, _ *activation.ApprovalClaim) { r.Commit.TTL += time.Second }},
		{"zero window", func(r *approval.Record, c *activation.ApprovalClaim) {
			r.Commit.IssuedAt = r.Commit.ExpiresAt
			c.IssuedAt = r.Commit.IssuedAt
			c.TTL = 0
		}},
		{"negative window", func(r *approval.Record, c *activation.ApprovalClaim) {
			r.Commit.IssuedAt = r.Commit.ExpiresAt.Add(time.Second)
			c.IssuedAt = r.Commit.IssuedAt
			c.TTL = -time.Second
		}},
		{"window exceeds original TTL", func(r *approval.Record, c *activation.ApprovalClaim) {
			r.Commit.IssuedAt = r.SubmittedAt.Add(-time.Second)
			c.IssuedAt = r.Commit.IssuedAt
			c.TTL = r.Request.TTL + time.Second
		}},
		{"commit expiry differs from ledger", func(r *approval.Record, c *activation.ApprovalClaim) {
			r.Commit.ExpiresAt = r.Commit.ExpiresAt.Add(-time.Second)
			c.ExpiresAt = r.Commit.ExpiresAt
			c.TTL -= time.Second
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			record, request := delayedApprovalWindow(t)
			tc.mutate(&record, &request.ApprovalClaim)
			err := validateApproval(record, request)
			if !errors.Is(err, activation.ErrAuthorizationDenied) && !errors.Is(err, activation.ErrAuthorizationBinding) {
				t.Fatalf("tampered window error=%v, want authorization rejection", err)
			}
		})
	}
}

func delayedApprovalWindow(t *testing.T) (approval.Record, activation.AuthorizationRequest) {
	t.Helper()
	submittedAt := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	issuedAt := submittedAt.Add(approval.WarningDelay)
	request := activation.AuthorizationRequest{Action: "promote", Target: activation.RuntimeTarget{Key: "plugin-window"}}
	gate := approval.NewGate(7)
	record, err := gate.Submit(submittedAt, approval.Request{
		ID: "approval-window", Risk: approval.RiskMedium, Scope: activation.ApprovalScope(request), PolicyEpoch: 7,
		TTL: 2 * time.Minute, Actor: "operator", SessionID: "session-window", ConfirmationLanguage: "en-US",
		IntentDigest: activation.ApprovalIntentDigest(request), Nonce: "nonce-window",
	})
	if err != nil {
		t.Fatal(err)
	}
	phrase, err := approval.ExpectedConfirmationPhrase("en-US")
	if err != nil {
		t.Fatal(err)
	}
	commit, err := gate.Confirm(issuedAt, record.ID, approval.Confirmation{
		WarningReadAt: submittedAt, PasswordConfirmed: true, SecondConfirmation: true, Local: true,
		ConfirmationID: "confirmation-window", Actor: record.Request.Actor, Scope: record.Request.Scope,
		PolicyEpoch: 7, SessionID: record.Request.SessionID, ConfirmationLanguage: "en-US", ConfirmationPhrase: phrase,
		IntentDigest: record.Request.IntentDigest, Nonce: record.Request.Nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, ok := gate.Get(record.ID)
	if !ok {
		t.Fatal("approved record missing")
	}
	if err := approval.ValidateRecordForAdapter(record); err != nil {
		t.Fatal(err)
	}
	request.ApprovalClaim = activation.ApprovalClaim{
		ApprovalID: record.ID, ConfirmationID: commit.ConfirmationID, Actor: commit.Actor,
		Scope: commit.Scope, PolicyEpoch: commit.PolicyEpoch, TTL: commit.ExpiresAt.Sub(commit.IssuedAt),
		IssuedAt: commit.IssuedAt, ExpiresAt: commit.ExpiresAt, IntentDigest: commit.IntentDigest,
		Nonce: commit.Nonce, SessionID: commit.SessionID,
	}
	return record, request
}
