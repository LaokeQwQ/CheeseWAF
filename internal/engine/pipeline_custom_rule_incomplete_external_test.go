package engine_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/rules"
)

type bodyMarkerDetector struct{}

func (bodyMarkerDetector) ID() string    { return "test.body-marker" }
func (bodyMarkerDetector) Name() string  { return "test body marker" }
func (bodyMarkerDetector) Priority() int { return 290 }
func (bodyMarkerDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if strings.Contains(string(reqCtx.DecodedBody), "attack_marker") {
		return &engine.DetectionResult{
			Detected: true, DetectorID: "test.body-marker", Category: "rce",
			Severity: engine.SeverityHigh, Action: engine.ActionBlock, Confidence: 0.99,
		}, nil
	}
	return nil, nil
}

func TestPipelineContinuesAfterIncompleteCustomJSONRuleInspection(t *testing.T) {
	compiled, err := rules.FromConfig([]config.CustomRuleConfig{{
		ID: "never-match", Name: "never match", Pattern: "NEVER_MATCH",
		Location: "body", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}

	var body strings.Builder
	body.WriteByte('{')
	for i := range 2050 {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"f%d":"v"`, i)
	}
	body.WriteString(`,"payload":"attack_marker"}`)
	request := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(request, "default")
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.Metadata["budget_exhausted_policy"] = "closed"

	result, err := engine.NewPipeline(rules.New(compiled), bodyMarkerDetector{}).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock || result.DetectorID != "test.body-marker" {
		t.Fatalf("later semantic detection did not run or lost to incomplete-input fail-mode: %+v", result)
	}
	if reqCtx.Metadata["detection_input_incomplete"] != true {
		t.Fatalf("incomplete custom-rule coverage was not retained for audit: %#v", reqCtx.Metadata)
	}
	if got := reqCtx.Metadata["detection_analysis_incomplete_reason"]; got != "custom_rule_json_field_limit" {
		t.Fatalf("incomplete reason=%#v, want custom_rule_json_field_limit", got)
	}
}
