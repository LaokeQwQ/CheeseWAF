package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
)

func TestApprovalCredentialBudgetCannotResetWithNewRequest(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	calls := 0
	f.handler.passwordVerifier = func(context.Context, ApprovalSession, string) (ApprovalCredentialProof, error) {
		calls++
		return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
	}
	for i := 0; i < 6; i++ {
		record := submitApprovalHTTP(t, f, fmt.Sprintf("budget-request-%d", i))
		challenge := startApprovalHTTP(t, f, record)
		f.advance(approval.WarningDelay)
		body := fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"password":"wrong","second_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase)
		response := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
		if i == 5 && response.Code != http.StatusTooManyRequests {
			t.Fatalf("new request bypassed credential budget: status=%d body=%s verifier calls=%d", response.Code, response.Body.String(), calls)
		}
	}
	if calls != 5 {
		t.Fatalf("credential verifier called %d times, want bounded 5", calls)
	}
}

func TestApprovalLocalityCannotBeProvedByLoopbackPeer(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/approvals/x/confirmation", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	if approvalHTTPRequestIsLocal(r) {
		t.Fatal("loopback proxy with no forwarding headers was accepted as local control transport")
	}
}

func TestApprovalHTTPThirdClickReusesBoundCredentialProof(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	calls := 0
	f.handler.passwordVerifier = func(context.Context, ApprovalSession, string) (ApprovalCredentialProof, error) {
		calls++
		if calls > 1 {
			return ApprovalCredentialProof{}, ErrApprovalCredentialRejected
		}
		return NewApprovalCredentialProof("single-use-credential-proof", true, true), nil
	}
	record := submitApprovalHTTP(t, f, "one-use-factor")
	challenge := startApprovalHTTP(t, f, record)
	f.advance(approval.WarningDelay)
	body := fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"password":"secret","second_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase)
	checkpoint := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if checkpoint.Code != http.StatusConflict {
		t.Fatalf("checkpoint status=%d body=%s", checkpoint.Code, checkpoint.Body.String())
	}
	body = fmt.Sprintf(`{"confirmation_id":%q,"confirmation_phrase":%q,"second_confirmation":true,"third_confirmation":true}`, challenge.ConfirmationID, challenge.Phrase)
	final := confirmApprovalHTTP(t, f, record, body, "operator", "session-operator", "127.0.0.1:1234")
	if final.Code != http.StatusOK || calls != 1 {
		t.Fatalf("third click reverified single-use factor: status=%d body=%s verifier calls=%d", final.Code, final.Body.String(), calls)
	}
}

func TestApprovalHTTPSelfApprovalRejected(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	record := submitApprovalHTTP(t, f, "self-approval")
	r := approvalHTTPRequest(http.MethodPost, "/api/approvals/"+record.ID+"/confirmation/start", `{}`, "requester", "session-requester", "admin", "127.0.0.1:1234")
	w := httptest.NewRecorder()
	f.handler.StartApprovalConfirmation(w, withApprovalRouteID(r, record.ID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("self approval status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestApprovalHTTPEnrolledMFACannotUsePasswordOnly(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	f.handler.passwordVerifier = func(context.Context, ApprovalSession, string) (ApprovalCredentialProof, error) {
		return NewMFAApprovalCredentialProof("enrolled-mfa-proof", true, false, true), nil
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	_, err := f.handler.verifyApprovalCredentials(r, ApprovalSession{}, approvalConfirmPayload{Password: "correct"})
	if err != ErrApprovalCredentialRejected {
		t.Fatalf("MFA password-only error=%v", err)
	}
}

func TestApprovalHTTPTOTPOnlyProofIsAccepted(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	f.handler.totpVerifier = func(context.Context, ApprovalSession, string) (ApprovalCredentialProof, error) {
		return NewApprovalCredentialProof("totp-only-proof", false, true), nil
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	proof, err := f.handler.verifyApprovalCredentials(r, ApprovalSession{}, approvalConfirmPayload{TOTPCode: "123456"})
	if err != nil || !proof.totpConfirmed || proof.passwordConfirmed {
		t.Fatalf("TOTP-only proof err=%v proof=%+v", err, proof)
	}
}

func TestApprovalHTTPClientCannotPreapproveOrLowerRisk(t *testing.T) {
	f := newApprovalHTTPFixture(t, true)
	for _, preapproved := range []bool{true, false} {
		body := fmt.Sprintf(`{"id":"risk-%t","scope":"crp:promote:key","risk":"low","pre_approved":%t,"policy_epoch":7,"ttl":"1m"}`, preapproved, preapproved)
		w := httptest.NewRecorder()
		r := approvalHTTPRequest(http.MethodPost, "/api/approvals", body, "requester", "session-requester", "admin", "127.0.0.1:1234")
		f.handler.SubmitApproval(w, r)
		if preapproved {
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "PREAPPROVAL") {
				t.Fatalf("preapproved status=%d body=%s", w.Code, w.Body.String())
			}
			continue
		}
		record, ok := f.gate.Get("risk-false")
		if w.Code != http.StatusOK || !ok || record.Request.Risk != approval.RiskHigh || record.Request.PreApproved || !record.Request.ClusterOperation {
			t.Fatalf("client selected risk: status=%d record=%+v", w.Code, record)
		}
	}
}
