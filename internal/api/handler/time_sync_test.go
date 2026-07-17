package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

type fakeTimeSyncService struct {
	status        timekeeper.Status
	reselectError error
	syncError     error
	reselectCalls int
	syncCalls     int
}

func (s *fakeTimeSyncService) Status() timekeeper.Status { return s.status }

func (s *fakeTimeSyncService) ReselectNow(context.Context) error {
	s.reselectCalls++
	return s.reselectError
}

func (s *fakeTimeSyncService) SyncNow(context.Context) error {
	s.syncCalls++
	return s.syncError
}

func TestTimeSyncStatusReportsCalibratedRuntimeState(t *testing.T) {
	cfg := config.Default()
	now := time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)
	service := &fakeTimeSyncService{status: timekeeper.Status{
		Primary: "time.google.com", Backup: "time.cloudflare.com", ActiveSource: "time.google.com",
		Synchronized: true, Offset: 125 * time.Millisecond, RTT: 18 * time.Millisecond, Stratum: 2,
		LastSuccess: now.Add(-time.Minute), LastAttempt: now.Add(-time.Minute),
	}}
	h := &Handler{Config: &cfg, TimeSync: service, now: func() time.Time { return now }}
	recorder := httptest.NewRecorder()
	h.TimeSyncStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/time-sync", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, expected := range []string{`"state":"synchronized"`, `"primary_source":"time.google.com"`, `"backup_source":"time.cloudflare.com"`, `"offset_ms":125`, `"rtt_ms":18`, `"current_time":"2026-07-15T10:00:00Z"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing %s in %s", expected, body)
		}
	}
}

func TestTimeSyncOperationsUseRuntimeService(t *testing.T) {
	cfg := config.Default()
	service := &fakeTimeSyncService{status: timekeeper.Status{Synchronized: true}}
	h := &Handler{Config: &cfg, TimeSync: service, now: time.Now}

	for _, tc := range []struct {
		name string
		run  func(http.ResponseWriter, *http.Request)
	}{
		{name: "reselect", run: h.ReselectTimeSync},
		{name: "sync", run: h.SyncTimeNow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			tc.run(recorder, httptest.NewRequest(http.MethodPost, "/api/system/time-sync/"+tc.name, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status code = %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
	if service.reselectCalls != 1 || service.syncCalls != 1 {
		t.Fatalf("operation calls = reselect:%d sync:%d", service.reselectCalls, service.syncCalls)
	}
}

func TestTimeSyncOperationRejectsDisabledBusyAndUnavailable(t *testing.T) {
	cfg := config.Default()
	cfg.TimeSync.Enabled = false
	h := &Handler{Config: &cfg, now: time.Now}
	recorder := httptest.NewRecorder()
	h.SyncTimeNow(recorder, httptest.NewRequest(http.MethodPost, "/api/system/time-sync/sync", nil))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "TIME_SYNC_DISABLED") {
		t.Fatalf("disabled response = %d: %s", recorder.Code, recorder.Body.String())
	}

	cfg.TimeSync.Enabled = true
	recorder = httptest.NewRecorder()
	h.SyncTimeNow(recorder, httptest.NewRequest(http.MethodPost, "/api/system/time-sync/sync", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "TIME_SYNC_UNAVAILABLE") {
		t.Fatalf("unavailable response = %d: %s", recorder.Code, recorder.Body.String())
	}

	h.TimeSync = &fakeTimeSyncService{syncError: timekeeper.ErrSyncInProgress}
	recorder = httptest.NewRecorder()
	h.SyncTimeNow(recorder, httptest.NewRequest(http.MethodPost, "/api/system/time-sync/sync", nil))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "TIME_SYNC_BUSY") {
		t.Fatalf("busy response = %d: %s", recorder.Code, recorder.Body.String())
	}

	h.TimeSync = &fakeTimeSyncService{syncError: errors.New("offline")}
	recorder = httptest.NewRecorder()
	h.SyncTimeNow(recorder, httptest.NewRequest(http.MethodPost, "/api/system/time-sync/sync", nil))
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "TIME_SYNC_FAILED") {
		t.Fatalf("failed response = %d: %s", recorder.Code, recorder.Body.String())
	}
}
