package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
)

func startApprovalHTTPBudgetChallenge(t *testing.T, f approvalHTTPFixture, record approval.Record, session string) ApprovalChallenge {
	t.Helper()
	response := httptest.NewRecorder()
	request := approvalHTTPRequest(http.MethodPost, "/api/approvals/"+record.ID+"/confirmation/start", `{"language":"en-US"}`, "operator", session, "admin", "127.0.0.1:1234")
	f.handler.StartApprovalConfirmation(response, withApprovalRouteID(request, record.ID))
	if response.Code != http.StatusOK {
		t.Fatalf("start code=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct{ Challenge ApprovalChallenge }
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data.Challenge
}

func TestApprovalHTTPCredentialBudgetsPruneExpiredFailureAndSuccess(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	for _, test := range []struct {
		session  string
		password string
		want     int
	}{
		{session: "failed-budget", password: "wrong", want: http.StatusForbidden},
		{session: "successful-budget", password: "secret", want: http.StatusConflict},
	} {
		record := submitApprovalHTTP(t, f, test.session)
		challenge := startApprovalHTTPBudgetChallenge(t, f, record, test.session)
		f.advance(approval.WarningDelay)
		body := fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"password":%q,"second_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase, test.password)
		response := confirmApprovalHTTP(t, f, record, body, "operator", test.session, "127.0.0.1:1234")
		if response.Code != test.want {
			t.Fatalf("%s code=%d body=%s", test.session, response.Code, response.Body.String())
		}
	}
	if got := len(f.handler.credentialBudgets); got != 2 {
		t.Fatalf("credential budgets after verification=%d, want 2", got)
	}
	f.advance(approvalCredentialLockWindow + time.Second)
	response := confirmApprovalHTTP(t, f, approval.Record{ID: "unknown"}, `{}`, "operator", "session-unknown", "127.0.0.1:1234")
	if response.Code != http.StatusConflict {
		t.Fatalf("unknown confirmation code=%d body=%s", response.Code, response.Body.String())
	}
	if got := len(f.handler.credentialBudgets); got != 0 {
		t.Fatalf("expired credential budgets retained=%d, want 0", got)
	}
}

func TestApprovalHTTPCredentialBudgetCapacityRejectsNewSessionWithoutEviction(t *testing.T) {
	for _, verifying := range []bool{false, true} {
		t.Run(fmt.Sprintf("verifying=%t", verifying), func(t *testing.T) {
			f := newApprovalHTTPFixture(t, true)
			record := submitApprovalHTTP(t, f, "budget-capacity")
			challenge := startApprovalHTTP(t, f, record)
			f.advance(approval.WarningDelay)
			const maxBudgets = 1024
			expiresAt := f.now.Add(approvalCredentialLockWindow)
			if verifying {
				expiresAt = f.now.Add(-time.Second)
			}
			budget := approvalCredentialBudget{failures: approvalCredentialMaxFailures, verifying: verifying, expiresAt: expiresAt}
			for i := 0; i < maxBudgets; i++ {
				f.handler.credentialBudgets[fmt.Sprintf("active-session-%d", i)] = budget
			}
			calls := 0
			f.handler.passwordVerifier = func(context.Context, ApprovalSession, string) (ApprovalCredentialProof, error) {
				calls++
				return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
			}
			body := fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"password":"wrong","second_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase)
			response := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
			if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "APPROVAL_CREDENTIAL_BUDGET_CAPACITY") {
				t.Fatalf("full credential budget code=%d body=%s", response.Code, response.Body.String())
			}
			if calls != 0 {
				t.Fatalf("capacity rejection called verifier %d times", calls)
			}
			if got := len(f.handler.credentialBudgets); got != maxBudgets {
				t.Fatalf("full budget table grew to %d entries, want %d", got, maxBudgets)
			}
			for key, got := range f.handler.credentialBudgets {
				if got != budget {
					t.Fatalf("active budget %q changed: %+v, want %+v", key, got, budget)
				}
			}
		})
	}
}

func TestApprovalHTTPCredentialBudgetCapacityAllowsExistingSession(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "budget-existing")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	expiresAt := f.now.Add(approvalCredentialLockWindow)
	for i := 0; i < 1023; i++ {
		f.handler.credentialBudgets[fmt.Sprintf("active-session-%d", i)] = approvalCredentialBudget{failures: approvalCredentialMaxFailures, expiresAt: expiresAt}
	}
	const budgetKey = "operator:session-operator"
	f.handler.credentialBudgets[budgetKey] = approvalCredentialBudget{failures: 1, expiresAt: expiresAt}
	body := fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"password":"wrong","second_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase)
	response := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if response.Code != http.StatusForbidden {
		t.Fatalf("existing budget code=%d body=%s", response.Code, response.Body.String())
	}
	if got := f.handler.credentialBudgets[budgetKey]; got.failures != 2 || got.verifying || got.expiresAt != expiresAt {
		t.Fatalf("existing failure budget reset or changed lifetime: %+v", got)
	}
	if got := len(f.handler.credentialBudgets); got != 1024 {
		t.Fatalf("existing budget table size=%d, want 1024", got)
	}
}

func TestApprovalHTTPCredentialBudgetCapacityRecoversAfterExpiry(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "budget-recovered")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	for i := 0; i < 1024; i++ {
		f.handler.credentialBudgets[fmt.Sprintf("expired-session-%d", i)] = approvalCredentialBudget{failures: approvalCredentialMaxFailures, expiresAt: f.now}
	}
	body := fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"password":"secret","second_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase)
	response := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "APPROVAL_THIRD_CONFIRMATION_REQUIRED") {
		t.Fatalf("confirmation after budget expiry code=%d body=%s", response.Code, response.Body.String())
	}
	budget, exists := f.handler.credentialBudgets["operator:session-operator"]
	if len(f.handler.credentialBudgets) != 1 || !exists || budget.failures != 0 || budget.verifying || !budget.expiresAt.Equal(f.now.Add(approvalCredentialLockWindow)) {
		t.Fatalf("expired budgets did not release capacity: %+v", f.handler.credentialBudgets)
	}
}

func TestApprovalHTTPCredentialBudgetPruningRetainsInFlightVerification(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	const budgetKey = "operator:session-operator"
	budget := approvalCredentialBudget{failures: 2, verifying: true, expiresAt: f.now.Add(-time.Second)}
	f.handler.credentialBudgets[budgetKey] = budget
	f.handler.credentialBudgets["expired-session"] = approvalCredentialBudget{expiresAt: f.now}
	response := confirmApprovalHTTP(t, f, approval.Record{ID: "unknown"}, `{}`, "operator", "session-operator", "127.0.0.1:1234")
	if response.Code != http.StatusConflict {
		t.Fatalf("unknown confirmation code=%d body=%s", response.Code, response.Body.String())
	}
	if len(f.handler.credentialBudgets) != 1 || f.handler.credentialBudgets[budgetKey] != budget {
		t.Fatalf("pruning lost in-flight budget or retained expired budget: %+v", f.handler.credentialBudgets)
	}
}
