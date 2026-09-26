package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
)

type cwedpExecutorFunc func(context.Context, consumer.Request) (consumer.Result, error)

func (f cwedpExecutorFunc) DownloadCWEDP(ctx context.Context, request consumer.Request) (consumer.Result, error) {
	return f(ctx, request)
}

func TestDownloadCWEDPUsesServerClaimsAndFreshPassword(t *testing.T) {
	h, store := newUserTestHandler(t)
	createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")
	var calls atomic.Int32
	h.CWEDPDownload = cwedpExecutorFunc(func(_ context.Context, request consumer.Request) (consumer.Result, error) {
		calls.Add(1)
		if request.Identity.ID != "admin-id" || request.Identity.ManagementSessionID != "session-a" || request.Password != "admin-password" {
			t.Fatalf("executor received incorrect server-derived identity: %+v", request)
		}
		return consumer.Result{JobID: "job-a", Source: cwedp.Source{ID: "registry-source"}, Staged: crp.RuntimeRecord{Slot: crp.RuntimeSlotStaged, Key: "demo", Version: "1.0.0", Revision: 2, ManifestIdentity: "manifest", ArtifactIdentity: "artifact"}}, nil
	})
	body := []byte(`{"password":"admin-password","policy_epoch":7,"ttl_seconds":60,"max_bytes":1}`)
	request := httptest.NewRequest(http.MethodPost, "/system/cwedp/download", bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "admin-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.DownloadCWEDP(recorder, request)
	if recorder.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("DownloadCWEDP status=%d calls=%d body=%s", recorder.Code, calls.Load(), recorder.Body.String())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"activation_performed":false`)) || !bytes.Contains(recorder.Body.Bytes(), []byte(`"stage_status":"staged"`)) {
		t.Fatalf("download response did not report staged-only result: %s", recorder.Body.String())
	}
}

func TestDownloadCWEDPRejectsSpoofedClaimsBeforeExecutor(t *testing.T) {
	h, store := newUserTestHandler(t)
	createUserFixture(t, store, "admin-id", "admin", "admin-password", "admin")
	var calls atomic.Int32
	h.CWEDPDownload = cwedpExecutorFunc(func(context.Context, consumer.Request) (consumer.Result, error) {
		calls.Add(1)
		return consumer.Result{}, nil
	})
	request := httptest.NewRequest(http.MethodPost, "/system/cwedp/download", bytes.NewReader([]byte(`{"password":"admin-password","policy_epoch":7,"ttl_seconds":60,"max_bytes":1}`)))
	request = request.WithContext(context.WithValue(request.Context(), middleware.UserContextKey, &middleware.Claims{Subject: "attacker-id", ID: "session-a", Username: "admin", Role: "admin"}))
	recorder := httptest.NewRecorder()
	h.DownloadCWEDP(recorder, request)
	if recorder.Code != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("spoofed claim status=%d calls=%d body=%s", recorder.Code, calls.Load(), recorder.Body.String())
	}
}
