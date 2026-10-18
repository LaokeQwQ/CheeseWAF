package semantic

import (
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// The 2022-2026 increment is deliberately narrow. It only claims a pair of
// shapes that reach an execution sink, not every reflection/API name that can
// appear in ordinary framework documentation. Broader OGNL, Spring, Servlet and
// deserialization shapes stay in research quarantine until they have a parser
// or an upstream-consistency check.
var ssti2026Direct = regexp.MustCompile(`(?is)(?:` +
	`#set\s*\([^)]*\)[\s\S]*(?:` +
	`(?:\.getclass\s*\(\s*\)\s*\.\s*|\.class\s*\.\s*|\.getclassloader\s*\(\s*\)\s*\.\s*loadclass\s*\(\s*)` +
	`(?:forname\s*\(\s*["']java\.lang\.(?:runtime|processbuilder)["']|["']java\.lang\.(?:runtime|processbuilder)["'])` +
	`|#set[\s\S]*?forname\s*\(\s*["']java\.lang\.(?:runtime|processbuilder)["']` +
	`)[\s\S]*\.\s*(?:exec|start)\s*\(|` +
	`(?:\*|@)\s*\{[^}]*(?:` +
	`t\s*\(\s*java\.lang\.(?:runtime|processbuilder)|` +
	`java\.lang\.(?:runtime|processbuilder)|` +
	`runtime\.getruntime\s*\(\s*\)` +
	`)[^}]*\.\s*(?:exec|start)\s*\(` +
	`)`)

func ssti2026Hint(lower string) bool {
	for _, marker := range []string{"#set", "*{", "@{", "#context", "#session", "#application", "#request", "class.forname", "scriptenginemanager", "methodhandles", "processbuilder"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func analyzeSSTI2026(candidate semanticCandidate) (Hit, bool) {
	// NFKC/lowercase here as well: an attacker who can read this file knows the
	// ASCII spelling and can try full-width or compatibility variants.
	raw := normalize(candidate.text)
	if !ssti2026Direct.MatchString(raw) {
		return Hit{}, false
	}
	reasons := map[string]bool{
		"syntax: Velocity/SpEL reflection reaches Runtime or ProcessBuilder":           true,
		"semantics: attacker-controlled template evaluation reaches process execution": true,
	}
	return hit(candidate, "ssti", engine.SeverityCritical, 0.92, reasons), true
}

// sstiArithmeticStandalone keeps the integer-only arithmetic probe tied to a
// value that is the entire template expression. A search sentence containing
// "{{7*7}} in documentation" is not a probe.
func sstiArithmeticStandalone(text string) bool {
	return sstiWholeBodyExpression.MatchString(strings.TrimSpace(text))
}

// lfiWrapperPathShape requires a wrapper to actually name a resource. A
// documentation sentence such as "php://filter is documented here" has the
// scheme but no path, resource, or filter chain; it must not become an LFI hit.
func lfiWrapperPathShape(lower string) bool {
	for _, prefix := range []string{"php://", "zip://", "phar://", "expect://", "file://"} {
		idx := strings.Index(lower, prefix)
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(lower[idx+len(prefix):])
		if rest == "" {
			continue
		}
		switch prefix {
		case "php://":
			if strings.HasPrefix(rest, "filter/") && (strings.Contains(rest, "resource=") || strings.Contains(rest, "convert.")) {
				return true
			}
			for _, stream := range []string{"input", "stdin", "memory", "temp", "fd/"} {
				if strings.HasPrefix(rest, stream) {
					return true
				}
			}
		case "expect://":
			return !strings.HasPrefix(rest, "in ") && !strings.HasPrefix(rest, "is ")
		case "file://":
			return strings.Contains(rest, "/") || strings.Contains(rest, "\\")
		default:
			if strings.Contains(rest, "/") {
				return true
			}
		}
	}
	return false
}
