package semantic

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type XXEDetector struct{ mode string }

func NewXXEDetector(mode string) *XXEDetector {
	if mode == "" {
		mode = "block"
	}
	return &XXEDetector{mode: mode}
}

func (d *XXEDetector) ID() string    { return "semantic.xxe" }
func (d *XXEDetector) Name() string  { return "XXE Semantic Detector" }
func (d *XXEDetector) Priority() int { return 360 }

func (d *XXEDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	result, err := NewAnalyzer(d.mode, "xxe").Detect(ctx, reqCtx)
	if result != nil {
		result.DetectorID = d.ID()
	}
	return result, err
}
