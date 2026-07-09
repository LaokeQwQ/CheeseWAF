package semantic

import (
	"context"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type SSTIDetector struct{ mode string }

func NewSSTIDetector(mode string) *SSTIDetector {
	if mode == "" {
		mode = "block"
	}
	return &SSTIDetector{mode: mode}
}
func (d *SSTIDetector) ID() string    { return "semantic.ssti" }
func (d *SSTIDetector) Name() string  { return "SSTI Semantic Detector" }
func (d *SSTIDetector) Priority() int { return 350 }

func (d *SSTIDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	result, err := NewAnalyzer(d.mode, "ssti").Detect(ctx, reqCtx)
	if result != nil {
		result.DetectorID = d.ID()
	}
	return result, err
}
