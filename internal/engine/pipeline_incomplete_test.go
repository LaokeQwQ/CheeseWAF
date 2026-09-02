package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type pipelineInputIncompleteError struct{ reason string }

func (e *pipelineInputIncompleteError) Error() string            { return "input analysis incomplete" }
func (e *pipelineInputIncompleteError) AnalysisIncomplete() bool { return e != nil }
func (e *pipelineInputIncompleteError) IncompleteReason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

type pipelineIncompleteDetector struct {
	id       string
	priority int
	result   *DetectionResult
	err      error
}

type pipelineBlockingDetector struct {
	id       string
	priority int
	started  chan<- struct{}
	release  <-chan struct{}
	result   *DetectionResult
}

func (d pipelineBlockingDetector) ID() string    { return d.id }
func (d pipelineBlockingDetector) Name() string  { return d.id }
func (d pipelineBlockingDetector) Priority() int { return d.priority }
func (d pipelineBlockingDetector) Detect(context.Context, *RequestContext) (*DetectionResult, error) {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-d.release
	return d.result, nil
}

func (d pipelineIncompleteDetector) ID() string    { return d.id }
func (d pipelineIncompleteDetector) Name() string  { return d.id }
func (d pipelineIncompleteDetector) Priority() int { return d.priority }
func (d pipelineIncompleteDetector) Detect(_ context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	if reqCtx.Metadata == nil {
		reqCtx.Metadata = map[string]any{}
	}
	if d.err != nil {
		reqCtx.Metadata["semantic_input_incomplete"] = true
		reqCtx.Metadata["semantic_input_incomplete_reason"] = "multipart_coverage_incomplete"
		reqCtx.Metadata["semantic_analysis_incomplete"] = true
		reqCtx.Metadata["semantic_analysis_incomplete_reason"] = "multipart_coverage_incomplete"
	}
	return d.result, d.err
}

func TestPipelineAppliesFailModeToTypedInputIncomplete(t *testing.T) {
	var budgetHookCalls atomic.Int32
	SetDetectionBudgetExhaustedHook(func() { budgetHookCalls.Add(1) })
	t.Cleanup(func() { SetDetectionBudgetExhaustedHook(nil) })

	tests := []struct {
		policy       string
		wantDetected bool
		wantAction   Action
	}{
		{policy: "open", wantDetected: false, wantAction: ActionPass},
		{policy: "observe", wantDetected: true, wantAction: ActionLog},
		{policy: "closed", wantDetected: true, wantAction: ActionChallenge},
	}
	for _, tc := range tests {
		t.Run(tc.policy, func(t *testing.T) {
			reqCtx := &RequestContext{
				Request:  httptest.NewRequest(http.MethodPost, "/upload", nil),
				Metadata: map[string]any{"budget_exhausted_policy": tc.policy},
			}
			result, err := NewPipeline(pipelineIncompleteDetector{
				id: "incomplete", priority: 290,
				err: &pipelineInputIncompleteError{reason: "multipart_coverage_incomplete"},
			}).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Detected != tc.wantDetected || result.Action != tc.wantAction {
				t.Fatalf("result=%+v, want detected=%t action=%v", result, tc.wantDetected, tc.wantAction)
			}
			if tc.wantDetected && result.Category != "detection_incomplete" {
				t.Fatalf("category=%q, want detection_incomplete", result.Category)
			}
			if reqCtx.Metadata["detection_analysis_incomplete"] != true || reqCtx.Metadata["detection_input_incomplete"] != true {
				t.Fatalf("missing incomplete metadata: %#v", reqCtx.Metadata)
			}
			if got := reqCtx.Metadata["detection_analysis_incomplete_reason"]; got != "multipart_coverage_incomplete" {
				t.Fatalf("incomplete reason=%#v", got)
			}
			if reqCtx.Metadata["detection_budget_exhausted"] == true {
				t.Fatalf("input coverage loss was counted as budget exhaustion: %#v", reqCtx.Metadata)
			}
			if reqCtx.Metadata["semantic_input_incomplete"] != true || reqCtx.Metadata["semantic_analysis_incomplete"] != true {
				t.Fatalf("semantic evidence was not merged: %#v", reqCtx.Metadata)
			}
		})
	}
	if got := budgetHookCalls.Load(); got != 0 {
		t.Fatalf("budget hook called %d times for input coverage errors", got)
	}
}

func TestPipelineRealBlockWinsOverParallelInputIncomplete(t *testing.T) {
	block := &DetectionResult{
		Detected: true, DetectorID: "confirmed", Category: "rce",
		Severity: SeverityCritical, Action: ActionBlock, Confidence: 0.99,
	}
	reqCtx := &RequestContext{
		Request:  httptest.NewRequest(http.MethodPost, "/upload", nil),
		Metadata: map[string]any{"budget_exhausted_policy": "closed"},
	}
	result, err := NewPipeline(
		pipelineIncompleteDetector{
			id: "incomplete", priority: 290,
			err: &pipelineInputIncompleteError{reason: "multipart_coverage_incomplete"},
		},
		pipelineIncompleteDetector{id: "confirmed", priority: 291, result: block},
	).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != ActionBlock || result.Category != "rce" {
		t.Fatalf("confirmed block lost to incomplete fail-mode: %+v", result)
	}
	if reqCtx.Metadata["detection_input_incomplete"] != true {
		t.Fatalf("block result lost incomplete audit metadata: %#v", reqCtx.Metadata)
	}
}

func TestPipelineDeadlineWinsAccountingWhenInputIsAlsoIncomplete(t *testing.T) {
	tests := []struct {
		name       string
		withBlock  bool
		wantAction Action
		wantCat    string
	}{
		{name: "deadline result", wantAction: ActionChallenge, wantCat: "detection_budget"},
		{name: "confirmed block still wins", withBlock: true, wantAction: ActionBlock, wantCat: "rce"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var budgetHookCalls atomic.Int32
			SetDetectionBudgetExhaustedHook(func() { budgetHookCalls.Add(1) })
			defer SetDetectionBudgetExhaustedHook(nil)

			started := make(chan struct{}, 1)
			release := make(chan struct{})
			detectors := []Detector{
				pipelineIncompleteDetector{
					id: "incomplete", priority: 290,
					err: &pipelineInputIncompleteError{reason: "multipart_coverage_incomplete"},
				},
				pipelineBlockingDetector{
					id: "timeout", priority: 291, started: started, release: release,
					result: &DetectionResult{
						Detected: true, DetectorID: "late", Category: "rce",
						Severity: SeverityCritical, Action: ActionBlock, Confidence: 0.99,
					},
				},
			}
			if tc.withBlock {
				detectors = append(detectors, pipelineIncompleteDetector{
					id: "confirmed", priority: 292,
					result: &DetectionResult{
						Detected: true, DetectorID: "confirmed", Category: "rce",
						Severity: SeverityCritical, Action: ActionBlock, Confidence: 0.99,
					},
				})
			}
			reqCtx := &RequestContext{
				Request:  httptest.NewRequest(http.MethodPost, "/upload", nil),
				Metadata: map[string]any{"budget_exhausted_policy": "closed"},
			}
			type outcome struct {
				result *DetectionResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := NewPipeline(detectors...).Detect(context.Background(), reqCtx)
				done <- outcome{result: result, err: err}
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				close(release)
				t.Fatal("timeout detector did not start")
			}
			var got outcome
			select {
			case got = <-done:
			case <-time.After(600 * time.Millisecond):
				close(release)
				t.Fatal("pipeline did not honor detector deadline")
			}
			close(release)
			if got.err != nil {
				t.Fatal(got.err)
			}
			if got.result == nil || got.result.Action != tc.wantAction || got.result.Category != tc.wantCat {
				t.Fatalf("result=%+v, want action=%v category=%q", got.result, tc.wantAction, tc.wantCat)
			}
			if reqCtx.Metadata["detection_budget_exhausted"] != true {
				t.Fatalf("deadline was hidden by input incomplete: %#v", reqCtx.Metadata)
			}
			if got := reqCtx.Metadata["detection_analysis_incomplete_reason"]; got != "pipeline_deadline" {
				t.Fatalf("incomplete reason=%#v, want pipeline_deadline", got)
			}
			if budgetHookCalls.Load() != 1 {
				t.Fatalf("budget hook calls=%d, want 1", budgetHookCalls.Load())
			}
		})
	}
}
