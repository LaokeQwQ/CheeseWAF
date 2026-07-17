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
	regexp.MustCompile(`(?i)\bon[a-z0-9_-]{3,}\s*=`),
	regexp.MustCompile(`(?i)<\s*(?:[a-z0-9_-]+\s*:\s*)?svg\b[^>]*\bon[a-z0-9_-]{3,}\s*=`),
	regexp.MustCompile(`(?i)<\s*xss\b[^>]*\bon[a-z0-9_-]{3,}\s*=`),
	// Additional attack vectors
	regexp.MustCompile(`(?i)\bonpointer(?:down|move|up|enter|leave|over|out)\s*=`),
	regexp.MustCompile(`(?i)\bontransitionend\s*=`),
	regexp.MustCompile(`(?i)\bonanimationstart\s*=`),
	regexp.MustCompile(`(?i)<\s*embed\b[^>]*\bsrc\s*=\s*['"]?\s*javascript\s*:`),
	regexp.MustCompile(`(?i)<\s*object\b[^>]*\bdata\s*=\s*['"]?\s*javascript\s*:`),
	regexp.MustCompile(`(?i)<\s*math\b[^>]*\bhref\s*=\s*['"]?\s*javascript\s*:`),
	regexp.MustCompile(`(?i)['"]\s*>?\s*<\s*/\s*(?:style|script|title|textarea|math|noscript)\s*>?\s*<\s*img\b`),
	regexp.MustCompile(`(?i)<\s*details\b[^>]*\bontoggle\s*=`),
	regexp.MustCompile(`(?i)\bjavascript\s*:\s*(?:[a-z_][a-z0-9_]*\s*\(|void\s*\()`),
}

var javascriptURLContext = regexp.MustCompile(`(?i)<[^>]+\b(?:href|src|srcset|xlink:href|formaction|action|poster|codebase|background|longdesc|profile|usemap)\s*=\s*['"]?\s*javascript\s*:`)
var xssDataURLContext = regexp.MustCompile(`(?i)<[^>]+\b(?:href|src|data|xlink:href|formaction|action|content|poster|codebase)\s*=\s*['"]?\s*data\s*:\s*(?:text/html|image/svg\+xml|application/xhtml\+xml)`)
var xssSrcdocContext = regexp.MustCompile(`(?i)<\s*iframe\b[^>]*\bsrcdoc\s*=`)
var xssMetaRefreshContext = regexp.MustCompile(`(?i)<\s*meta\b[^>]*\bcontent\s*=\s*['"]?[^'">]*url\s*=\s*javascript\s*:`)
var xssStyleExecutionContext = regexp.MustCompile(`(?i)<[^>]+\bstyle\s*=\s*['"]?[^>]*(?:\bexpression\s*\(|\burl\s*\(\s*javascript\s*:)`)
var xssCSSInjectionPattern = regexp.MustCompile(`(?i)<\s*style\b[^>]*>|\bstyle\s*=\s*['"]?[^>]*(?:\bexpression\s*\(|behavior\s*:\s*url|@import\s+url\s*\(\s*javascript)`)

// Modern XSS vectors from HTML5sec and PayloadsAllTheThings
var xssModernPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*button\b[^>]*\bformaction\s*=\s*['"]?\s*javascript\s*:`),                          // button formaction XSS
	regexp.MustCompile(`(?i)<\s*video\b[^>]*\bposter\s*=\s*['"]?\s*javascript\s*:`),                               // video poster XSS
	regexp.MustCompile(`(?i)<\s*(?:audio|source|track)\b[^>]*\bsrc\s*=\s*['"]?\s*javascript\s*:`),                 // audio/source XSS
	regexp.MustCompile(`(?i)<\s*svg\b[^>]*\bonload\s*=`),                                                          // SVG onload XSS
	regexp.MustCompile(`(?i)<\?xml-stylesheet\b[^>]*\bhref\s*=\s*['"]?\s*javascript\s*:`),                         // XML stylesheet XSS
	regexp.MustCompile(`(?i)charset\s*=\s*['"]x-imap4-modified-utf7['"]`),                                         // UTF-7 charset XSS
	regexp.MustCompile(`(?i)x-mac-farsi`),                                                                         // Mac Farsi charset XSS
	regexp.MustCompile(`(?i)crypto\.generateCRMFRequest\s*\(`),                                                    // Browser crypto API XSS
	regexp.MustCompile(`(?i)<\s*body\b[^>]*\bonscroll\s*=.*alert`),                                                // scroll-based XSS
	regexp.MustCompile(`(?i)<\s*input\b[^>]*\bonfocus\s*=\s*(?:write|eval)`),                                      // input onfocus XSS
	regexp.MustCompile(`(?i)<\s*input\b[^>]*\bpattern\s*=\s*['"].*\(\(a\+\?\.\)a\)\+\$`),                          // ReDoS via pattern attr
	regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}|&#x[0-9a-f]+;){3,}\s*(?:alert|eval|write|prompt|confirm)\s*\(`),     // multi-hex-encoded function call
	regexp.MustCompile(`(?i)style\s*=\s*['"]-o-link(-source)?\s*:\s*['"]?javascript`),                             // Opera CSS link XSS
	regexp.MustCompile(`(?i)<\s*x\b[^>]*\brepeat\s*=`),                                                            // template repeat DoS/XSS
	regexp.MustCompile(`(?i)(?:importScripts|postMessage)\s*\(\s*['"]\s*(?:data|javascript):`),                    // Worker-based XSS
	regexp.MustCompile(`(?i)set\s*\(\s*['"]?(?:innerHTML|outerHTML)\s*['"]?\s*,\s*`),                              // DOM manipulation XSS
	regexp.MustCompile(`(?i)(?:\{\s*\}\s*=\s*alert|_\s*=\s*alert|call\s*\(\s*alert\s*\))`),                        // JS shorthand execution
	regexp.MustCompile(`(?i)(?:\/\*\*\/|\\u[0-9a-f]{4}\\u[0-9a-f]{4})`),                                           // JS comment/unicode obfuscation
	regexp.MustCompile(`(?i)<\s*[a-z0-9]+\b[^>]*\bxlink:href\s*=\s*['"]?data\s*:\s*text\/html`),                   // SVG xlink data URI XSS
	regexp.MustCompile(`(?i)<\s*(?:frame|iframe)\b[^>]*\bsrc\s*=\s*['"]?\s*(?:javascript|data):`),                 // frame/iframe XSS
	regexp.MustCompile(`(?i)\b(?:\\u[0-9a-f]{4}|\\x[0-9a-f]{2}){2,}\b(?:alert|eval|prompt|confirm|write|open)\b`), // unicode-encoded function name
	regexp.MustCompile(`(?i)(?:&#\d{2,3};){4,}`),                                                                  // decimal HTML entity encoding chain
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

func (d *XSSDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	candidates := []string{payload, decoder.Decode(payload).Text, decoder.DeepDecode(payload).Text}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Deep tokenization first (fast, pure Go; libinjection-compatible)
		if engine.XSSLibinjectionFingerprint(candidate) {
			return &engine.DetectionResult{
				Detected: true, DetectorID: d.ID(), Category: "xss", Severity: engine.SeverityHigh, Action: actionForMode(d.mode),
				Message: "XSS token fingerprint matched", Confidence: 0.90, Payload: strings.TrimSpace(candidate),
			}, nil
		}
		normalized := normalize(candidate)
		if executableXSSContext(normalized) {
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
	return nil, nil
}

func executableXSSContext(normalized string) bool {
	for _, pattern := range xssPatterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	for _, pattern := range xssModernPatterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}
	return javascriptURLContext.MatchString(normalized) ||
		xssDataURLContext.MatchString(normalized) ||
		xssSrcdocContext.MatchString(normalized) ||
		xssMetaRefreshContext.MatchString(normalized) ||
		xssStyleExecutionContext.MatchString(normalized) ||
		xssCSSInjectionPattern.MatchString(normalized)
}
