package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/audit"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

type crpActivationExecutorFunc func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error)

type auditEventAppenderFunc struct {
	events     []audit.Event
	contexts   []context.Context
	contextOK  []bool
	err        error
	failOnCall int
}

func (f *auditEventAppenderFunc) Append(ctx context.Context, event audit.Event) (audit.Record, error) {
	f.events = append(f.events, event)
	f.contexts = append(f.contexts, ctx)
	f.contextOK = append(f.contextOK, ctx != nil && ctx.Err() == nil)
	if f.err != nil && (f.failOnCall == 0 || len(f.events) == f.failOnCall) {
		return audit.Record{}, f.err
	}
	return audit.Record{}, nil
}

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
	if received.Action != crp.RuntimeActionPromote || received.Key != "official/demo" || received.ExpectedRevision != 7 || received.RequestID == "" {
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

func TestCRPActivationWritesMetadataOnlyAuditEvents(t *testing.T) {
	h, _ := newUserTestHandler(t)
	appender := &auditEventAppenderFunc{}
	h.AuditRuntime = appender
	h.AuditPolicyEpoch = 9
	h.RequireAuditRuntime = true
	h.CRPActivation = crpActivationExecutorFunc(func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
		return activation.ActivationResult{
			Phase:           activation.PhaseActive,
			Record:          crp.RuntimeRecord{Key: "official/demo", Version: "1.0.0", Revision: 8, ManifestIdentity: "manifest-a"},
			Fence:           activation.Fence{Epoch: 9, Revision: 9},
			RequestID:       "crp-request-a",
			AuthorizationID: "crp-authorization-a",
			ConfirmationID:  "crp-confirmation-a",
		}, nil
	})
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":1,"probe_timeout_seconds":5}`)
	request := httptest.NewRequest(http.MethodPost, "/system/crp/activate", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.ActivateCRP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ActivateCRP status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(appender.events) != 2 {
		t.Fatalf("audit events=%d, want start and completion: %+v", len(appender.events), appender.events)
	}
	start, complete := appender.events[0], appender.events[1]
	if start.Outcome != audit.OutcomeStarted || complete.Outcome != audit.OutcomeSuccess || start.Class != audit.EventClassCritical || complete.Class != audit.EventClassCritical {
		t.Fatalf("unexpected audit lifecycle: start=%+v complete=%+v", start, complete)
	}
	if start.CorrelationID == "" || complete.CorrelationID != "crp-request-a" || complete.AuthorizationID != "crp-authorization-a" || complete.ConfirmationID != "crp-confirmation-a" {
		t.Fatalf("audit correlation is incomplete: start=%+v complete=%+v", start, complete)
	}
	for _, event := range appender.events {
		if event.PolicyEpoch != 9 || event.Actor != "admin:admin-id" || event.SessionID != "session-a" || event.TenantID != "tenant:local" {
			t.Fatalf("audit identity binding lost: %+v", event)
		}
		if strings.Contains(event.Resource, "official/demo") || strings.Contains(event.Reason, "descriptor") {
			t.Fatalf("audit event contains request content: %+v", event)
		}
	}
}

func TestCRPActivationAuditSurvivesRequestCancellationAndPreservesRole(t *testing.T) {
	h, _ := newUserTestHandler(t)
	appender := &auditEventAppenderFunc{}
	h.AuditRuntime = appender
	h.AuditPolicyEpoch = 9
	h.RequireAuditRuntime = true
	h.CRPActivation = crpActivationExecutorFunc(func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
		return activation.ActivationResult{Phase: activation.PhaseActive, Record: crp.RuntimeRecord{Key: "official/demo", Version: "1.0.0", Revision: 8}}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, middleware.UserContextKey, &middleware.Claims{Subject: "operator-id", ID: "session-a", Username: "operator", Role: "operator"})
	cancel()
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":1,"probe_timeout_seconds":5}`)
	request := httptest.NewRequest(http.MethodPost, "/system/crp/activate", bytes.NewReader(body)).WithContext(ctx)
	recorder := httptest.NewRecorder()
	h.ActivateCRP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("canceled request status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(appender.events) != 2 || appender.events[0].Actor != "operator:operator-id" || appender.events[1].Actor != "operator:operator-id" {
		t.Fatalf("role was not preserved in audit events: %+v", appender.events)
	}
	for _, ok := range appender.contextOK {
		if !ok {
			t.Fatalf("audit append received canceled context")
		}
	}
}

func TestCRPActivationReturnsAuditFailureWhenCompletionCannotBeDurablyAppended(t *testing.T) {
	h, _ := newUserTestHandler(t)
	appender := &auditEventAppenderFunc{err: errors.New("journal unavailable"), failOnCall: 2}
	h.AuditRuntime = appender
	h.AuditPolicyEpoch = 9
	h.RequireAuditRuntime = true
	h.CRPActivation = crpActivationExecutorFunc(func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
		return activation.ActivationResult{}, activation.ErrApprovalClaimUnavailable
	})
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":1,"probe_timeout_seconds":5}`)
	request := httptest.NewRequest(http.MethodPost, "/system/crp/activate", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.ActivateCRP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("completion audit failure status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCRPActivationRequiresDurableAuditWhenProductionWired(t *testing.T) {
	h, _ := newUserTestHandler(t)
	h.RequireAuditRuntime = true
	called := false
	h.CRPActivation = crpActivationExecutorFunc(func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error) {
		called = true
		return activation.ActivationResult{}, nil
	})
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":1,"probe_timeout_seconds":5}`)
	request := httptest.NewRequest(http.MethodPost, "/system/crp/activate", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.ActivateCRP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("missing production audit status=%d called=%t body=%s", recorder.Code, called, recorder.Body.String())
	}
}
