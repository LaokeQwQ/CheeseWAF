package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var lfiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:\.\.[/\\]){2,}`),
	regexp.MustCompile(`(?i)(?:/etc/passwd|/etc/shadow|/proc/self/environ|boot\.ini|win\.ini|windows[/\\]win\.ini)`),
	regexp.MustCompile(`(?i)(?:php|zip|data|file)://`),
	regexp.MustCompile(`(?i)(?:WEB-INF/web\.xml|META-INF/MANIFEST\.MF)`),
	regexp.MustCompile(`(?i)(?:^|/|\b)(?:\.aws/credentials|\.git/config|\.env|\.ssh/(?:id_rsa|id_dsa)|wp-config(?:\.php)?|config/(?:database|parameters|settings)\.(?:php|ya?ml|json)|WEB-INF/web\.xml)(?:$|\b)`),
}

type LFIDetector struct {
	mode string
}

func NewLFIDetector(mode string) *LFIDetector {
	if mode == "" {
		mode = "block"
	}
	return &LFIDetector{mode: mode}
}

func (d *LFIDetector) ID() string    { return "semantic.lfi" }
func (d *LFIDetector) Name() string  { return "Local File Inclusion Semantic Detector" }
func (d *LFIDetector) Priority() int { return 330 }

func (d *LFIDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		for _, pattern := range lfiPatterns {
			if pattern.MatchString(trimmed) {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "lfi",
					Severity:   engine.SeverityHigh,
					Action:     actionForMode(d.mode),
					Message:    "local file inclusion pattern matched",
					Confidence: 0.86,
					Payload:    trimmed,
				}, nil
			}
		}
	}
	return nil, nil
}
