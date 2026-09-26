package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp/activation"
)

type crpActivationRouteExecutor func(context.Context, activation.AsyncRequest) (activation.ActivationResult, error)

func (f crpActivationRouteExecutor) ExecuteCRPActivation(ctx context.Context, request activation.AsyncRequest) (activation.ActivationResult, error) {
	return f(ctx, request)
}

func TestRouterCRPActivationIsInvisibleWithoutProductionExecutor(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)
	response := perform(router, http.MethodPost, "/api/system/crp/activate", "", []byte(`{}`))
	if response.Code != http.StatusNotFound {
		t.Fatalf("CRP activation route exposed without executor: %d %s", response.Code, response.Body.String())
	}
}

func TestRouterCRPActivationRequiresWriteSystem(t *testing.T) {
	_, cfg, store, _, _ := newAuthzTestRouterState(t, nil)
	var calls int
	router := NewRouter(Options{
		Config:             cfg,
		Store:              store,
		Secret:             "crp-activation-route-test-secret",
		AssistantApprovals: ai.NewApprovalStore(),
		CRPActivation: crpActivationRouteExecutor(func(_ context.Context, request activation.AsyncRequest) (activation.ActivationResult, error) {
			calls++
			if request.Action != crp.RuntimeActionPromote {
				t.Fatalf("unexpected activation action: %s", request.Action)
			}
			return activation.ActivationResult{Phase: activation.PhaseActive, Record: crp.RuntimeRecord{Key: request.Key, Version: "1.0.0", Revision: 8}, Fence: activation.Fence{Epoch: 7, Revision: 9}}, nil
		}),
	})
	adminToken := loginAuthzUser(t, router, "admin", "admin-password")
	readerToken := loginAuthzUser(t, router, "reader", "reader-password")
	body := []byte(`{"plugin_key":"official/demo","expected_revision":7,"descriptor":{"plugin_id":"official/demo","runtime":"sidecar"},"observe_probes":1,"canary_probes":1,"probe_timeout_seconds":5}`)
	if response := perform(router, http.MethodPost, "/api/system/crp/activate", readerToken, body); response.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("readonly CRP activation status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	if response := perform(router, http.MethodPost, "/api/system/crp/activate", adminToken, body); response.Code != http.StatusOK || calls != 1 {
		t.Fatalf("admin CRP activation status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
}
