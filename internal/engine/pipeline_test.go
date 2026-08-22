package engine

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPipelineReturnsLogOnlyDetection(t *testing.T) {
	result := &DetectionResult{
		Detected:   true,
		DetectorID: "test.log",
		Category:   "sqli",
		Severity:   SeverityHigh,
		Action:     ActionLog,
		Confidence: 0.88,
	}
	reqCtx := &RequestContext{}

	got, err := NewPipeline(staticPipelineDetector{id: "log", result: result}).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Action != ActionLog || got.DetectorID != "test.log" {
		t.Fatalf("expected log-only detection to be returned, got %#v", got)
	}
	if len(reqCtx.Results) != 1 || reqCtx.Results[0].Action != ActionLog {
		t.Fatalf("expected log-only detection in request results, got %#v", reqCtx.Results)
	}
}

func TestPipelineBlockDetectionOverridesEarlierLogDetection(t *testing.T) {
	logResult := &DetectionResult{
		Detected:   true,
		DetectorID: "test.log",
		Category:   "sqli",
		Severity:   SeverityHigh,
		Action:     ActionLog,
		Confidence: 0.88,
	}
	blockResult := &DetectionResult{
		Detected:   true,
		DetectorID: "test.block",
		Category:   "xss",
		Severity:   SeverityHigh,
		Action:     ActionBlock,
		Confidence: 0.91,
	}
	reqCtx := &RequestContext{}

	got, err := NewPipeline(
		staticPipelineDetector{id: "log", priority: 10, result: logResult},
		staticPipelineDetector{id: "block", priority: 20, result: blockResult},
	).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Action != ActionBlock || got.DetectorID != "test.block" {
		t.Fatalf("expected blocking detection to take precedence, got %#v", got)
	}
	if len(reqCtx.Results) != 2 {
		t.Fatalf("expected both detections in request results, got %#v", reqCtx.Results)
	}
}

type staticPipelineDetector struct {
	id       string
	priority int
	result   *DetectionResult
}

func (d staticPipelineDetector) ID() string { return d.id }
func (d staticPipelineDetector) Name() string {
	if d.id == "" {
		return "static"
	}
	return d.id
}
func (d staticPipelineDetector) Priority() int { return d.priority }
func (d staticPipelineDetector) Detect(context.Context, *RequestContext) (*DetectionResult, error) {
	return d.result, nil
}

func TestPipelineBudgetExhaustedPolicies(t *testing.T) {
	slow := &countingDetector{
		id: "slow-pre", priority: 10,
		fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			// Exceed the 100ms pipeline budget.
			timer := time.NewTimer(150 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				return nil, nil
			}
		},
	}

	t.Run("open passes", func(t *testing.T) {
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "open"}}
		got, err := NewPipeline(slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if reqCtx.Metadata["detection_budget_exhausted"] != true {
			t.Fatalf("expected budget exhausted flag, got %#v", reqCtx.Metadata)
		}
		if got != nil && got.Detected {
			t.Fatalf("open policy must not detect, got %#v", got)
		}
	})

	t.Run("observe logs", func(t *testing.T) {
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "observe"}}
		got, err := NewPipeline(slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Detected || got.Action != ActionLog || got.Category != "detection_budget" {
			t.Fatalf("expected observe log result, got %#v", got)
		}
	})

	t.Run("closed challenges", func(t *testing.T) {
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || !got.Detected || got.Action != ActionChallenge || got.Category != "detection_budget" {
			t.Fatalf("expected closed challenge result, got %#v", got)
		}
	})

	t.Run("block wins over closed budget", func(t *testing.T) {
		blocker := staticPipelineDetector{
			id: "block-early", priority: 5,
			result: &DetectionResult{
				Detected: true, DetectorID: "block-early", Category: "sqli",
				Severity: SeverityHigh, Action: ActionBlock, Confidence: 0.95,
			},
		}
		// Put a slow detector after the block so budget would fire if we continued;
		// block returns immediately from pre-filter phase before budget.
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(blocker, slow).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || got.Action != ActionBlock || got.DetectorID != "block-early" {
			t.Fatalf("expected real block to win, got %#v", got)
		}
	})

	t.Run("single semantic detector closed challenges on budget", func(t *testing.T) {
		// Production hot path: only priority>=290 detector (no pre-filter).
		slowSemantic := &countingDetector{
			id: "slow-semantic", priority: 290,
			fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
				timer := time.NewTimer(150 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
					return nil, nil
				}
			},
		}
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(slowSemantic).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if reqCtx.Metadata["detection_budget_exhausted"] != true {
			t.Fatalf("expected budget flag on single-analyzer path, got %#v", reqCtx.Metadata)
		}
		if got == nil || !got.Detected || got.Action != ActionChallenge || got.Category != "detection_budget" {
			t.Fatalf("expected closed challenge on single semantic path, got %#v", got)
		}
	})

	t.Run("clean finish is not challenged when deadline races after success", func(t *testing.T) {
		// Detector finishes successfully; incomplete flag unset → no budget challenge.
		fast := &countingDetector{
			id: "fast-semantic", priority: 290,
			fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
				return &DetectionResult{Detected: false, Action: ActionPass}, nil
			},
		}
		reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": "closed"}}
		got, err := NewPipeline(fast).Detect(context.Background(), reqCtx)
		if err != nil {
			t.Fatal(err)
		}
		if reqCtx.Metadata["detection_budget_exhausted"] == true {
			t.Fatalf("clean finish must not mark budget exhausted: %#v", reqCtx.Metadata)
		}
		if got != nil && got.Detected && got.Category == "detection_budget" {
			t.Fatalf("clean finish must not become budget challenge, got %#v", got)
		}
	})
}

func TestPipelineSemanticGroupConcurrentMerge(t *testing.T) {
	var started atomic.Int32
	slow := &countingDetector{
		id: "slow-semantic", priority: 290,
		fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			started.Add(1)
			// Wait until peer also started — proves concurrency.
			deadline := time.Now().Add(200 * time.Millisecond)
			for started.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if reqCtx.Metadata == nil {
				reqCtx.Metadata = map[string]any{}
			}
			reqCtx.Metadata["from_slow"] = true
			return &DetectionResult{
				Detected: true, DetectorID: "slow-semantic", Category: "sqli",
				Severity: SeverityHigh, Action: ActionLog, Confidence: 0.8,
			}, nil
		},
	}
	fast := &countingDetector{
		id: "fast-semantic", priority: 291,
		fn: func(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
			started.Add(1)
			deadline := time.Now().Add(200 * time.Millisecond)
			for started.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if reqCtx.Metadata == nil {
				reqCtx.Metadata = map[string]any{}
			}
			reqCtx.Metadata["semantic_analysis"] = "from_fast"
			return &DetectionResult{
				Detected: true, DetectorID: "fast-semantic", Category: "xss",
				Severity: SeverityHigh, Action: ActionBlock, Confidence: 0.95,
			}, nil
		},
	}
	reqCtx := &RequestContext{SiteID: "s1", Metadata: map[string]any{"pre": true}}
	got, err := NewPipeline(slow, fast).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Action != ActionBlock || got.DetectorID != "fast-semantic" {
		t.Fatalf("expected concurrent block winner, got %#v", got)
	}
	if started.Load() < 2 {
		t.Fatalf("expected concurrent start, started=%d", started.Load())
	}
	if reqCtx.Metadata["pre"] != true {
		t.Fatalf("pre-filter metadata lost: %#v", reqCtx.Metadata)
	}
	if reqCtx.Metadata["semantic_analysis"] != "from_fast" {
		t.Fatalf("expected semantic metadata merge, got %#v", reqCtx.Metadata)
	}
	if len(reqCtx.Results) != 2 {
		t.Fatalf("expected 2 results, got %#v", reqCtx.Results)
	}
}

func TestPipelineReusesSharedSemanticWorkers(t *testing.T) {
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	_ = semanticJobs()
	deadline := time.Now().Add(time.Second)
	for sharedSemanticWorkers.started.Load() != int64(workers) && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	started := sharedSemanticWorkers.started.Load()
	if started != int64(workers) {
		t.Fatalf("started workers=%d, want %d", started, workers)
	}

	pipeline := NewPipeline(
		staticPipelineDetector{id: "one", priority: 290},
		staticPipelineDetector{id: "two", priority: 291},
	)
	for range 20 {
		if _, err := pipeline.Detect(context.Background(), &RequestContext{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := sharedSemanticWorkers.started.Load(); got != started {
		t.Fatalf("per-request workers started: before=%d after=%d", started, got)
	}
}

func TestPipelineGuardOverloadAppliesConfiguredFailMode(t *testing.T) {
	tests := []struct {
		name         string
		priority     int
		policy       string
		wantAction   Action
		wantDetected bool
	}{
		{name: "pre-filter open", priority: 10, policy: "open", wantAction: ActionPass},
		{name: "pre-filter observe", priority: 10, policy: "observe", wantAction: ActionLog, wantDetected: true},
		{name: "pre-filter closed", priority: 10, policy: "closed", wantAction: ActionChallenge, wantDetected: true},
		{name: "semantic-only open", priority: 290, policy: "open", wantAction: ActionPass},
		{name: "semantic-only observe", priority: 290, policy: "observe", wantAction: ActionLog, wantDetected: true},
		{name: "semantic-only closed", priority: 290, policy: "closed", wantAction: ActionChallenge, wantDetected: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			saturateGuardSlots(t)
			var called atomic.Int32
			detector := &countingDetector{
				id: "malicious-payload", priority: tc.priority,
				fn: func(context.Context, *RequestContext) (*DetectionResult, error) {
					called.Add(1)
					return &DetectionResult{
						Detected: true, DetectorID: "malicious-payload", Category: "rce",
						Severity: SeverityCritical, Action: ActionBlock, Confidence: 0.99,
					}, nil
				},
			}
			reqCtx := &RequestContext{Metadata: map[string]any{"budget_exhausted_policy": tc.policy}}

			got, err := NewPipeline(detector).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if called.Load() != 0 {
				t.Fatalf("detector ran despite saturated guard capacity: calls=%d", called.Load())
			}
			if got == nil || got.Action != tc.wantAction || got.Detected != tc.wantDetected {
				t.Fatalf("policy %q result = %#v, want action=%s detected=%v", tc.policy, got, tc.wantAction, tc.wantDetected)
			}
			if reqCtx.Metadata["detection_analysis_incomplete"] != true || reqCtx.Metadata["detection_overloaded"] != true {
				t.Fatalf("overload must explicitly mark incomplete analysis: %#v", reqCtx.Metadata)
			}
			if reason := reqCtx.Metadata["detection_analysis_incomplete_reason"]; reason != "guard_overload" {
				t.Fatalf("incomplete reason = %#v, want guard_overload", reason)
			}
			if reqCtx.Metadata["detection_budget_exhausted"] != true {
				t.Fatalf("overload must enter budget fail-mode: %#v", reqCtx.Metadata)
			}
			if tc.policy != "open" && got.Category != "detection_budget" {
				t.Fatalf("fail-mode category = %q, want detection_budget", got.Category)
			}
		})
	}
}

func TestDetectionBudgetHookConcurrentRegistration(t *testing.T) {
	SetDetectionBudgetExhaustedHook(nil)
	t.Cleanup(func() { SetDetectionBudgetExhaustedHook(nil) })

	var calls atomic.Int64
	hook := func() { calls.Add(1) }
	SetDetectionBudgetExhaustedHook(hook)

	const goroutines = 8
	const iterations = 250
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range iterations {
				SetDetectionBudgetExhaustedHook(hook)
			}
		}()
		go func() {
			defer wg.Done()
			for range iterations {
				reqCtx := &RequestContext{Metadata: map[string]any{
					"budget_exhausted_policy": "open",
				}}
				_ = finalizeBudgetExhausted(reqCtx, nil)
			}
		}()
	}
	wg.Wait()

	if got, want := calls.Load(), int64(goroutines*iterations); got != want {
		t.Fatalf("hook calls = %d, want %d", got, want)
	}
}

func saturateGuardSlots(t *testing.T) {
	t.Helper()
	waitGuardSlotsIdle(t)
	if got := cap(guardSlots); got != maxInflightGuards {
		t.Fatalf("guard slot capacity = %d, want %d", got, maxInflightGuards)
	}
	n := cap(guardSlots)
	for i := 0; i < n; i++ {
		guardSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < n; i++ {
			select {
			case <-guardSlots:
			case <-time.After(2 * time.Second):
				t.Errorf("timed out draining guard slot %d/%d", i+1, n)
				return
			}
		}
		waitGuardSlotsIdle(t)
	})
}

func waitGuardSlotsIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(guardSlots) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("guard slots did not drain, leftover=%d", len(guardSlots))
		}
		time.Sleep(time.Millisecond)
	}
}

type countingDetector struct {
	id       string
	priority int
	fn       func(context.Context, *RequestContext) (*DetectionResult, error)
}

func (d *countingDetector) ID() string    { return d.id }
func (d *countingDetector) Name() string  { return d.id }
func (d *countingDetector) Priority() int { return d.priority }
func (d *countingDetector) Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	return d.fn(ctx, reqCtx)
}
