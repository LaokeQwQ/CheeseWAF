package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
)

type cwedpRouteExecutor func(context.Context, consumer.Request) (consumer.Result, error)

func (f cwedpRouteExecutor) DownloadCWEDP(ctx context.Context, request consumer.Request) (consumer.Result, error) {
	return f(ctx, request)
}

func TestRouterCWEDPDownloadIsInvisibleWithoutConsumer(t *testing.T) {
	router, _, _ := newAuthzTestRouter(t)
	response := perform(router, http.MethodPost, "/api/system/cwedp/download", "", []byte(`{}`))
	if response.Code != http.StatusNotFound {
		t.Fatalf("CWEDP route exposed without a consumer: %d %s", response.Code, response.Body.String())
	}
}

func TestRouterCWEDPDownloadRequiresWriteSystemAndSessionIdentity(t *testing.T) {
	_, cfg, store, _, _ := newAuthzTestRouterState(t, nil)
	var calls int
	router := NewRouter(Options{
		Config:             cfg,
		Store:              store,
		Secret:             "cwedp-route-test-secret",
		AssistantApprovals: ai.NewApprovalStore(),
		CWEDPDownload: cwedpRouteExecutor(func(_ context.Context, request consumer.Request) (consumer.Result, error) {
			calls++
			if request.Identity.ID != "admin-id" || request.Identity.ManagementSessionID == "" {
				t.Fatalf("consumer did not receive session-derived identity: %+v", request.Identity)
			}
			return consumer.Result{JobID: "job-a", Source: cwedp.Source{ID: "source-a"}, Staged: crp.RuntimeRecord{Slot: crp.RuntimeSlotStaged, Key: "demo", Version: "1.0.0"}}, nil
		}),
	})
	adminToken := loginAuthzUser(t, router, "admin", "admin-password")
	readerToken := loginAuthzUser(t, router, "reader", "reader-password")
	body := []byte(`{"password":"admin-password","policy_epoch":7,"ttl_seconds":60,"max_bytes":1}`)
	if response := perform(router, http.MethodPost, "/api/system/cwedp/download", readerToken, body); response.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("readonly CWEDP request status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	if response := perform(router, http.MethodPost, "/api/system/cwedp/download", adminToken, body); response.Code != http.StatusOK || calls != 1 {
		t.Fatalf("admin CWEDP request status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
}
