package engine

import (
	"context"
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

type countingDetector struct {
	id       string
	priority int
	fn       func(context.Context, *RequestContext) (*DetectionResult, error)
}

func (d *countingDetector) ID() string       { return d.id }
func (d *countingDetector) Name() string     { return d.id }
func (d *countingDetector) Priority() int    { return d.priority }
func (d *countingDetector) Detect(ctx context.Context, reqCtx *RequestContext) (*DetectionResult, error) {
	return d.fn(ctx, reqCtx)
}
