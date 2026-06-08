package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var rcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:;|&&|\|\||\|)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat)\b`),
	regexp.MustCompile(`(?i)(?:\$\(|` + "`" + `)\s*(?:cat|id|whoami|uname|curl|wget|bash|sh|zsh|dash|pwsh|powershell|cmd|python3?|perl|php|ruby|node|nc|ncat|netcat|socat)\b`),
	regexp.MustCompile(`(?i)(?:/bin/(?:sh|bash)|cmd\.exe|powershell\.exe)`),
	regexp.MustCompile(`(?i)(?:curl|wget)\s+[^|;&]+(?:\||;|&&)\s*(?:sh|bash)`),
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:bash|sh|zsh|dash|ksh)\s+-c\b`),
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])cmd(?:\.exe)?\s*/c\s+(?:whoami|id|dir|type|powershell|certutil|curl|wget|ping|nslookup)\b`),
	regexp.MustCompile(`(?i)(?:^|[=&\s;|])(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,160}\s-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{12,}`),
	regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b[^\r\n]{0,200}\b(?:downloadstring|new-object|net\.webclient|frombase64string)\b`),
	regexp.MustCompile(`(?i)(?:python3?|perl|php|ruby|node)\s+(?:-c|-e|-r)\b`),
	regexp.MustCompile(`(?i)(?:^|[=&\s])(?:/usr)?/bin/(?:perl|python3?|php|ruby|node|gunzip|unxz|ab|ansible|chef|cscli|visudo)\b`),
	regexp.MustCompile(`(?i)(?:^|[=&\s])(?:cat|head|tail|less|more|type)(?:\s|\$\{?ifs\}?)+/(?:etc|proc|var|root|home)\b`),
	regexp.MustCompile(`(?i)(?:\$SHELL|\$\{SHELL\})\s+-c\b`),
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
