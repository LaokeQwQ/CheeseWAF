package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var rcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:;|&&|\|\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|powershell|cmd)(?:\s|$)`),
	regexp.MustCompile(`(?i)(?:\$\(|` + "`" + `)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|powershell|cmd)`),
	regexp.MustCompile(`(?i)(?:/bin/(?:sh|bash)|cmd\.exe|powershell\.exe)`),
	regexp.MustCompile(`(?i)(?:curl|wget)\s+[^|;&]+(?:\||;|&&)\s*(?:sh|bash)`),
}

type RCEDetector struct {
	mode string
}

func NewRCEDetector(mode string) *RCEDetector {
	if mode == "" {
		mode = "block"
	}
	return &RCEDetector{mode: mode}
}

func (d *RCEDetector) ID() string    { return "semantic.rce" }
func (d *RCEDetector) Name() string  { return "Command Injection Semantic Detector" }
func (d *RCEDetector) Priority() int { return 320 }

func (d *RCEDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		for _, pattern := range rcePatterns {
			if pattern.MatchString(trimmed) {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "rce",
					Severity:   engine.SeverityCritical,
					Action:     actionForMode(d.mode),
					Message:    "command injection pattern matched",
					Confidence: 0.84,
					Payload:    trimmed,
				}, nil
			}
		}
	}
	return nil, nil
}
