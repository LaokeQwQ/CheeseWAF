package semantic

import (
	"context"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

type NoSQLiDetector struct{ mode string }

func NewNoSQLiDetector(mode string) *NoSQLiDetector {
	if mode == "" { mode = "block" }
	return &NoSQLiDetector{mode: mode}
}
func (d *NoSQLiDetector) ID() string    { return "semantic.nosqli" }
func (d *NoSQLiDetector) Name() string  { return "NoSQL Injection Semantic Detector" }
func (d *NoSQLiDetector) Priority() int { return 340 }

func (d *NoSQLiDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, c := range candidates {
		lower := strings.ToLower(c)
		// MongoDB operators in URL params or JSON bodies
		ops := []string{"$ne", "$gt", "$lt", "$gte", "$lte", "$regex", "$nin", "$in", "$where", "$or", "$nor", "$exists", "$eq", "$all", "$size", "$mod", "$type", "$elemMatch", "$function"}
		count := 0
		for _, op := range ops { if strings.Contains(lower, op) { count++ } }
		if count >= 2 {
			return &engine.DetectionResult{Detected: true, DetectorID: d.ID(), Category: "nosqli", Severity: engine.SeverityHigh, Action: actionForMode(d.mode), Message: "NoSQL injection: multiple MongoDB operators detected", Confidence: 0.88, Payload: strings.TrimSpace(c)}, nil
		}
	}
	return nil, nil
}
