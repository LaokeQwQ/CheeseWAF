package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var sstiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{.*?\}\}`),           // Jinja2/Twig/mustache
	regexp.MustCompile(`\$\{.*?\}`),             // FreeMarker/Velocity/Groovy
	regexp.MustCompile(`<%=.*?%>`),              // ERB/EJS
	regexp.MustCompile(`#\{.*?\}`),              // Ruby/Slim
	regexp.MustCompile(`\{%.*?%\}`),             // Twig/Jinja2 blocks
	regexp.MustCompile(`\[\[.*?\]\]`),           // Thymeleaf
	regexp.MustCompile(`\{\{=.*?\}\}`),          // Vue/Handlebars raw
	regexp.MustCompile(`__class__|__mro__|__subclasses__|__globals__|__builtins__`), // Python RCE chains
	regexp.MustCompile(`T\(java\.lang\.Runtime\)\.getRuntime\(\)`), // Spring EL RCE
	regexp.MustCompile(`freemarker\.template\.utility\.Execute`),   // FreeMarker Execute
	regexp.MustCompile(`registerUndefinedFilterCallback`),          // Twig filter callback
	regexp.MustCompile(`process\.mainModule\.require`),             // Node.js RCE
}

type SSTIDetector struct{ mode string }

func NewSSTIDetector(mode string) *SSTIDetector {
	if mode == "" { mode = "block" }
	return &SSTIDetector{mode: mode}
}
func (d *SSTIDetector) ID() string    { return "semantic.ssti" }
func (d *SSTIDetector) Name() string  { return "SSTI Semantic Detector" }
func (d *SSTIDetector) Priority() int { return 350 }

func (d *SSTIDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text}
	for _, c := range candidates {
		trimmed := strings.TrimSpace(c)
		for _, p := range sstiPatterns {
			if p.MatchString(trimmed) {
				return &engine.DetectionResult{Detected: true, DetectorID: d.ID(), Category: "ssti", Severity: engine.SeverityCritical, Action: actionForMode(d.mode), Message: "server-side template injection pattern matched", Confidence: 0.86, Payload: trimmed}, nil
			}
		}
	}
	return nil, nil
}
