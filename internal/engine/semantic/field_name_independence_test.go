package semantic

import (
	"net/url"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// C3 — detection must rest on the value's structure, not on the parameter name.
//
// The four payloads below are complete attack values: an internal URL, a
// MongoDB operator document, an executable URL scheme, and a traversal path.
// Each one used to be invisible under an arbitrary field name ("q") because the
// only thing that made it a sink was the field-name allowlist.
func TestFieldNameIndependenceForStructuralPayloads(t *testing.T) {
	a := NewAnalyzer("block", 3)
	cases := []struct {
		name, value, category string
	}{
		{"ssrf-metadata-url", "http://169.254.169.254/", "ssrf"},
		{"nosqli-operator-document", `{"$ne":null}`, "nosqli"},
		{"xss-javascript-url", "javascript:alert(1)", "xss"},
		{"lfi-traversal", "../../etc/passwd", "lfi"},
	}
	blocked := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/x?q="+url.QueryEscape(tc.value), "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected %s detection for %q under field name q", tc.category, tc.value)
			}
			if got.Category != tc.category {
				t.Fatalf("category = %q, want %q", got.Category, tc.category)
			}
			if got.Action == engine.ActionBlock {
				blocked++
			}
		})
	}
	// The plan's acceptance bar is 3 of 4; the implementation targets all four.
	if blocked < 3 {
		t.Fatalf("blocked %d/4 structural payloads, want >= 3", blocked)
	}
}

// The structural rule must not make ordinary values blockable. Each case is a
// value an application legitimately accepts under a generic field name.
func TestFieldNameIndependenceKeepsBenignValuesClean(t *testing.T) {
	a := NewAnalyzer("block", 3)
	cases := []string{
		"hello",
		"http://example.com/page?x=1",
		"https://example.com/docs",
		`{"page":2,"size":20}`,
		"javascript is a programming language",
		"the docs at https://example.com/guide explain this",
		`{"name":"alice"}`,
		"..;/",
	}
	for _, value := range cases {
		t.Run(value, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", "/x?q="+url.QueryEscape(value), "", "")
			if got != nil && got.Action == engine.ActionBlock {
				t.Fatalf("benign value %q was blocked: %+v", value, got)
			}
		})
	}
}

// Same-origin telemetry suppression must survive: a tracking endpoint echoing
// the site's own absolute URL through conventional fields is not an SSRF pivot.
func TestFieldNameIndependenceKeepsSameOriginTelemetryClean(t *testing.T) {
	a := NewAnalyzer("block", 3)
	target := "/track?url=" + url.QueryEscape("https://shop.test/cart") +
		"&referrer=" + url.QueryEscape("https://shop.test/cart") +
		"&href=" + url.QueryEscape("https://shop.test/cart")
	got := detectOnTarget(t, a, "GET", target, "", "")
	if got != nil && got.Action == engine.ActionBlock {
		t.Fatalf("same-origin telemetry reference was blocked: %+v", got)
	}
}
