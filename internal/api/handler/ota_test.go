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
