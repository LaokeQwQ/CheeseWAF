package semantic

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// C1 — matrix-segment path expressions.
//
// Tomcat and other servlet containers strip path parameters (";jsessionid=…")
// before resolving a path, so "..;/" reaches the filesystem as "../". A request
// parameter carrying that shape is a traversal even though it contains no
// literal "../" sequence, and the engine previously saw nothing but the
// sensitive target behind it.
func TestLFIMatrixSegmentTraversalInParameterValue(t *testing.T) {
	a := NewAnalyzer("block", 3)
	for _, target := range []string{
		"/download?file=" + url.QueryEscape("..;/etc/passwd"),
		"/download?file=" + url.QueryEscape("..;/..;/etc/passwd"),
		"/download?file=" + url.QueryEscape("/a/..;/etc/passwd"),
	} {
		t.Run(target, func(t *testing.T) {
			got := detectOnTarget(t, a, "GET", target, "", "")
			if got == nil || !got.Detected {
				t.Fatalf("expected matrix-segment traversal to be detected")
			}
			if got.Category != "lfi" {
				t.Fatalf("category = %q, want lfi", got.Category)
			}
			if got.Action != engine.ActionBlock {
				t.Fatalf("action = %v, want block", got.Action)
			}
		})
	}
}

// The matrix pattern must not turn prose ellipses into path traversal. "…" and
// "..." are ordinary punctuation; only a "..;" followed by a separator is a
// matrix segment.
func TestLFIMatrixSegmentPatternKeepsProseClean(t *testing.T) {
	a := NewAnalyzer("block", 3)
	for _, value := range []string{"...;/x", "..foo;bar", "well...;/x", ";jsessionid=abc"} {
		t.Run(value, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://x/x?q="+url.QueryEscape(value), nil)
			reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
			got, err := a.Detect(t.Context(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got != nil {
				t.Fatalf("expected no hit for %q, got %+v", value, got)
			}
			if review := reqCtx.Metadata["review_candidate"]; review != nil {
				t.Fatalf("expected no review candidate for %q, got %+v", value, review)
			}
		})
	}
}

// The reason text is part of the review contract: a matrix segment is a syntax
// observation, not proof of traversal or of a stream wrapper. The two words are
// what blockableHit greps for, so leaking either would silently promote a bare
// "..;/" to a block.
func TestLFIMatrixSegmentReasonIsNotTraversalOrWrapper(t *testing.T) {
	candidate := semanticCandidate{
		input: InputPoint{Source: "query", Name: "file"},
		text:  "..;/..;/admin",
	}
	hit, ok := analyzeLFI(candidate)
	if !ok {
		t.Fatal("expected a hit for a matrix-segment path expression")
	}
	if !strings.Contains(hit.Syntax, "matrix-segment path expression") {
		t.Fatalf("syntax = %q, want a matrix-segment reason", hit.Syntax)
	}
	if strings.Contains(strings.ToLower(hit.Syntax), "traversal") || strings.Contains(strings.ToLower(hit.Syntax), "wrapper") {
		t.Fatalf("syntax = %q must not mention traversal or wrapper", hit.Syntax)
	}
	// Evidence alone (no sensitive target) is review material, not a block.
	if (&Analyzer{mode: "block", paranoiaLevel: 3}).blockableHit(hit) {
		t.Fatal("a matrix segment without a sensitive target must not be blockable")
	}
}
