package semantic

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type NoSQLiDetector struct{ mode string }

func NewNoSQLiDetector(mode string) *NoSQLiDetector {
	if mode == "" {
		mode = "block"
	}
	return &NoSQLiDetector{mode: mode}
}
func (d *NoSQLiDetector) ID() string    { return "semantic.nosqli" }
func (d *NoSQLiDetector) Name() string  { return "NoSQL Injection Semantic Detector" }
func (d *NoSQLiDetector) Priority() int { return 340 }

func (d *NoSQLiDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	result, err := NewAnalyzer(d.mode, "nosqli").Detect(ctx, reqCtx)
	if result != nil {
		result.DetectorID = d.ID()
	}
	return result, err
}
