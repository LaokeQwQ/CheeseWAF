package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var xxePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<!DOCTYPE\s+[^>]+>`),
	regexp.MustCompile(`(?is)<!ENTITY\s+[^>]+(?:SYSTEM|PUBLIC)\s+["']`),
	regexp.MustCompile(`(?i)(?:file|php|expect|http|https)://`),
	regexp.MustCompile(`(?i)%[a-z0-9_.-]+;`),
}

type XXEDetector struct {
	mode string
}

func NewXXEDetector(mode string) *XXEDetector {
	if mode == "" {
		mode = "block"
	}
	return &XXEDetector{mode: mode}
}

func (d *XXEDetector) ID() string    { return "semantic.xxe" }
func (d *XXEDetector) Name() string  { return "XXE Semantic Detector" }
func (d *XXEDetector) Priority() int { return 340 }

func (d *XXEDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, candidate := range candidates {
		text := strings.TrimSpace(candidate)
		if !strings.Contains(strings.ToLower(text), "<!doctype") && !strings.Contains(strings.ToLower(text), "<!entity") {
			continue
		}
		matches := 0
		for _, pattern := range xxePatterns {
			if pattern.MatchString(text) {
				matches++
			}
		}
		if matches >= 2 {
			return &engine.DetectionResult{
				Detected:   true,
				DetectorID: d.ID(),
				Category:   "xxe",
				Severity:   engine.SeverityHigh,
				Action:     actionForMode(d.mode),
				Message:    "external XML entity pattern matched",
				Confidence: 0.84,
				Payload:    text,
			}, nil
		}
	}
	return nil, nil
}
