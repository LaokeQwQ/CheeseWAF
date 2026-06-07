package engine

import (
	"context"
	"testing"
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
