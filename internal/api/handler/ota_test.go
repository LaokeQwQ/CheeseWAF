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
	"github.com/LaokeQwQ/CheeseWAF/internal/ota"
)

type fixedClock struct{ at *time.Time }

func (c fixedClock) Now() time.Time { return *c.at }

type otaCheckStub struct {
	candidate ota.Candidate
	err       error
	calls     int
}

func (s *otaCheckStub) Check(_ context.Context, _ ota.Request) (ota.Candidate, error) {
	s.calls++
	return s.candidate, s.err
}

type otaStateStub struct {
	state ota.LastKnownGood
	err   error
}

func (s otaStateStub) Load(context.Context) (ota.LastKnownGood, error) {
	return s.state, s.err
}

func TestOTAStatusRemainsExecutorUnavailableWithoutActivationBoundary(t *testing.T) {
	cfg := config.Default()
	cfg.Update.OTA.Enabled = true
	cfg.Update.OTA.Channel = "stable"
	h := New(Options{Config: &cfg})
	recorder := httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", recorder.Code)
	}
	if body := recorder.Body.String(); body == "" || !containsAll(body, "EXECUTOR_UNAVAILABLE", "read_only") {
		t.Fatalf("body=%s", body)
	}
}

func TestOTAStatusReturnsReadOnlyCandidateAndSequenceErrors(t *testing.T) {
	cfg := config.Default()
	cfg.Update.OTA.Enabled = true
	cfg.Update.OTA.Channel = "canary"
	// Error mapping is asserted per call; caching would serve the first result.
	cfg.Update.OTA.CheckInterval = 0
	candidate := ota.Candidate{
		ReleaseID:       "official/demo@1.0.0#2",
		Version:         "1.0.0",
		ReleaseSequence: 2,
		IndexSequence:   3,
		SignatureStatus: "verified",
	}
	stub := &otaCheckStub{candidate: candidate}
	h := New(Options{
		Config:    &cfg,
		OTAClient: stub,
		OTAState:  otaStateStub{state: ota.LastKnownGood{IndexSequence: 1, ReleaseSequence: 1, ReleaseID: "official/demo@1.0.0#1", UpdatedAt: time.Unix(1, 0).UTC()}},
	})
	recorder := httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if recorder.Code != http.StatusOK || !containsAll(recorder.Body.String(), "candidate_available", "official/demo@1.0.0#2", "EXECUTOR_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	stub.err = ota.ErrSequenceRollback
	recorder = httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if recorder.Code != http.StatusOK || !containsAll(recorder.Body.String(), "SEQUENCE_ROLLBACK") {
		t.Fatalf("rollback status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestOTAStatusMapsInvalidStateAndDisabledConfig(t *testing.T) {
	cfg := config.Default()
	h := New(Options{Config: &cfg, OTAState: otaStateStub{err: errors.New("corrupt")}})
	recorder := httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if !containsAll(recorder.Body.String(), "DISABLED") {
		t.Fatalf("disabled body=%s", recorder.Body.String())
	}

	cfg.Update.OTA.Enabled = true
	h = New(Options{Config: &cfg, OTAClient: &otaCheckStub{}, OTAState: otaStateStub{err: errors.New("corrupt")}})
	recorder = httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if !containsAll(recorder.Body.String(), "STATE_INVALID") {
		t.Fatalf("invalid-state body=%s", recorder.Body.String())
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}

// ota.check_interval bounds how often the console poll reaches the release
// origin: the second request inside the window is served from the cache.
func TestOTAStatusCachesWithinCheckInterval(t *testing.T) {
	cfg := config.Default()
	cfg.Update.OTA.Enabled = true
	cfg.Update.OTA.Channel = "stable"
	cfg.Update.OTA.CheckInterval = time.Hour
	stub := &otaCheckStub{candidate: ota.Candidate{ReleaseID: "official/demo@1.0.0#2", Version: "1.0.0", ReleaseSequence: 2, IndexSequence: 3}}
	now := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	h := New(Options{Config: &cfg, OTAClient: stub, Clock: fixedClock{at: &now}})

	for i := 0; i < 3; i++ {
		recorder := httptest.NewRecorder()
		h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}
	if stub.calls != 1 {
		t.Fatalf("origin called %d times inside the interval, want 1", stub.calls)
	}

	now = now.Add(2 * time.Hour)
	recorder := httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if stub.calls != 2 {
		t.Fatalf("origin called %d times after the interval, want 2", stub.calls)
	}
}

// A canceled request must not poison the cache: the next visitor performs a
// real check instead of seeing a context error for the whole interval.
func TestOTAStatusDoesNotCacheCanceledRequests(t *testing.T) {
	cfg := config.Default()
	cfg.Update.OTA.Enabled = true
	cfg.Update.OTA.Channel = "stable"
	cfg.Update.OTA.CheckInterval = time.Hour
	stub := &otaCheckStub{candidate: ota.Candidate{ReleaseID: "official/demo@1.0.0#2", Version: "1.0.0", ReleaseSequence: 2, IndexSequence: 3}}
	h := New(Options{Config: &cfg, OTAClient: stub})

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	h.OTAStatus(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/system/ota", nil).WithContext(canceled))
	if stub.calls != 1 {
		t.Fatalf("origin calls after canceled request = %d", stub.calls)
	}

	recorder := httptest.NewRecorder()
	h.OTAStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
	if stub.calls != 2 {
		t.Fatalf("origin calls = %d, want a fresh check after cancellation", stub.calls)
	}
	if !strings.Contains(recorder.Body.String(), "candidate_available") {
		t.Fatalf("body=%s", recorder.Body.String())
	}
}

// Concurrent console polls share one origin check for the same channel.
func TestOTAStatusSingleFlightsConcurrentChecks(t *testing.T) {
	cfg := config.Default()
	cfg.Update.OTA.Enabled = true
	cfg.Update.OTA.Channel = "stable"
	cfg.Update.OTA.CheckInterval = time.Hour
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	stub := &blockingOTAClient{
		candidate: ota.Candidate{ReleaseID: "official/demo@1.0.0#2", Version: "1.0.0", ReleaseSequence: 2, IndexSequence: 3},
		started:   started,
		release:   release,
	}
	h := New(Options{Config: &cfg, OTAClient: stub})

	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			h.OTAStatus(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/system/ota", nil))
			done <- struct{}{}
		}()
	}
	<-started
	close(release)
	<-done
	<-done
	if stub.calls != 1 {
		t.Fatalf("origin calls = %d, want 1 shared check", stub.calls)
	}
}

type blockingOTAClient struct {
	candidate ota.Candidate
	started   chan struct{}
	release   chan struct{}
	calls     int
}

func (c *blockingOTAClient) Check(ctx context.Context, _ ota.Request) (ota.Candidate, error) {
	c.calls++
	select {
	case c.started <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
		return c.candidate, nil
	case <-ctx.Done():
		return ota.Candidate{}, ctx.Err()
	}
}
