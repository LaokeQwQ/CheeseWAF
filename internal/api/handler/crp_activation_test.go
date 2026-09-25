package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

type crpActivationExecutorFunc func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error)

func (f crpActivationExecutorFunc) ExecuteCRPActivation(ctx context.Context, request activation.AsyncRequest) (activation.ActivationResult, error) {
	return f(ctx, request)
}

func TestCRPActivationUsesServerSessionAndCannotInjectAuthority(t *testing.T) {
	h, _ := newUserTestHandler(t)
	var received activation.AsyncRequest
	h.CRPActivation = crpActivationExecutorFunc(func(_ context.Context, request activation.AsyncRequest) (activation.ActivationResult, error) {
		received = request
		return activation.ActivationResult{
			Phase:  activation.PhaseActive,
			Record: crp.RuntimeRecord{Key: "official/demo", Version: "1.0.0", Revision: 8, ManifestIdentity: "manifest-a"},
			Fence:  activation.Fence{Epoch: 7, Revision: 9},
		}, nil
	})
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":2,"probe_timeout_seconds":5}`)
	request := httptest.NewRequest(http.MethodPost, "/system/crp/activate", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.ActivateCRP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ActivateCRP status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if received.Action != crp.RuntimeActionPromote || received.Key != "official/demo" || received.ExpectedRevision != 7 {
		t.Fatalf("executor received wrong request: %+v", received)
	}
	if received.Fence != (activation.Fence{}) || received.Confirmation != nil {
		t.Fatalf("HTTP request injected authority: %+v", received)
	}
}

func TestCRPRollbackRequiresAuthenticatedSession(t *testing.T) {
	h, _ := newUserTestHandler(t)
	called := false
	h.CRPActivation = crpActivationExecutorFunc(func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
		called = true
		return activation.ActivationResult{}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/system/crp/rollback", bytes.NewReader([]byte(`{}`)))
	recorder := httptest.NewRecorder()
	h.RollbackCRP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("unauthenticated rollback status=%d called=%t body=%s", recorder.Code, called, recorder.Body.String())
	}
}

func TestCRPActivationMapsMissingApprovalToConflict(t *testing.T) {
	h, _ := newUserTestHandler(t)
	h.CRPActivation = crpActivationExecutorFunc(func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
		return activation.ActivationResult{}, activation.ErrApprovalClaimUnavailable
	})
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":1,"probe_timeout_seconds":5}`)
	request := httptest.NewRequest(http.MethodPost, "/system/crp/activate", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.ActivateCRP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("missing approval status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
