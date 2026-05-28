package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*(?:[a-z0-9_-]+\s*:\s*)?script\b`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)\bon[a-z0-9_-]{3,}\s*=`),
	regexp.MustCompile(`(?i)<\s*iframe\b`),
	regexp.MustCompile(`(?i)<\s*(?:[a-z0-9_-]+\s*:\s*)?svg\b[^>]*\bon[a-z0-9_-]{3,}\s*=`),
	regexp.MustCompile(`(?i)<\s*xss\b[^>]*\bon[a-z0-9_-]{3,}\s*=`),
}

type XSSDetector struct {
	mode string
}

func NewXSSDetector(mode string) *XSSDetector {
	if mode == "" {
		mode = "block"
	}
	return &XSSDetector{mode: mode}
}

func (d *XSSDetector) ID() string    { return "semantic.xss" }
func (d *XSSDetector) Name() string  { return "XSS Semantic Detector" }
func (d *XSSDetector) Priority() int { return 310 }

func (d *XSSDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, candidate := range candidates {
		for _, pattern := range xssPatterns {
			if pattern.MatchString(candidate) {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "xss",
					Severity:   engine.SeverityHigh,
					Action:     actionForMode(d.mode),
					Message:    "XSS payload pattern matched",
					Confidence: 0.86,
					Payload:    strings.TrimSpace(candidate),
				}, nil
			}
		}
	}
	return nil, nil
}
