package semantic

import (
	"net/url"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// C2 — the integer arithmetic probe is a complete template expression.
//
// "{{7*7}}" is the canonical confirmation probe: a response of 49 proves the
// engine evaluated attacker-supplied template syntax. It used to be downgraded
// to Medium/0.78 because the only evidence was an integer multiplication, which
// left it below the default High/0.85 policy threshold. The expression is the
// whole value on every surface below, so there is no prose to mistake for data.
func TestSSTIIntegerProbeBlocksOnEverySurface(t *testing.T) {
	a := NewAnalyzer("block", 3)
	cases := []struct{ name, method, target, contentType, body string }{
		{"query", "GET", "/search?q=" + url.QueryEscape("{{7*7}}"), "", ""},
		{"form", "POST", "/search", "application/x-www-form-urlencoded", "q=" + url.QueryEscape("{{7*7}}")},
		{"json", "POST", "/search", "application/json", `{"q":"{{7*7}}"}`},
		{"path", "GET", "/search/" + url.PathEscape("{{7*7}}"), "", ""},
		{"spaced-query", "GET", "/search?q=" + url.QueryEscape("{{ 7 * 7 }}"), "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, tc.method, tc.target, tc.contentType, tc.body)
			if got == nil || !got.Detected {
				t.Fatalf("expected SSTI detection, got none")
			}
			if got.Category != "ssti" {
				t.Fatalf("category = %q, want ssti", got.Category)
			}
			if got.Action != engine.ActionBlock {
				t.Fatalf("action = %v, want block", got.Action)
			}
			if got.Severity < engine.SeverityHigh {
				t.Fatalf("severity = %v, want >= high", got.Severity)
			}
			if got.Confidence < 0.85 {
				t.Fatalf("confidence = %.2f, want >= 0.85", got.Confidence)
			}
		})
	}
}

// The document gate must survive the confidence raise: a technical article that
// quotes the probe as subject matter is not a live template evaluation.
func TestSSTIIntegerProbeInDocumentationStaysClean(t *testing.T) {
	doc := `## Template injection

Server-side template injection appears when user input is concatenated into a
template. A well-known probe is:

` + "```text" + `
{{7*7}}
` + "```" + `

If the response contains 49, the engine evaluated the expression. Sandbox the
template environment and never build templates from request data. This section
is explanatory prose, not a live probe.
`
	a := NewAnalyzer("block", 3)
	got := detectOnTarget(t, a, "POST", "/api/documents", "text/markdown", doc)
	if got != nil && got.Action == engine.ActionBlock {
		t.Fatalf("documentation quoting the probe was blocked: %+v", got)
	}
}

// Prose that merely mentions the expression inside a longer value is data.
func TestSSTIIntegerProbeEmbeddedInSentenceStaysClean(t *testing.T) {
	a := NewAnalyzer("block", 3)
	value := "why does {{7*7}} evaluate on my staging server"
	got := detectOnTarget(t, a, "GET", "/search?q="+url.QueryEscape(value), "", "")
	if got != nil && got.Action == engine.ActionBlock {
		t.Fatalf("sentence mentioning the probe was blocked: %+v", got)
	}
}
