package semantic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// The candidate extractor sizes its slice from the work actually present and
// only builds the fingerprint map once the candidate list is long enough for the
// linear exact compare to stop being the cheaper guard. Both are performance
// changes that must not move behaviour, so these tests pin the properties that
// make that true.

// TestDedupIsExactAcrossTheMapThreshold walks candidate counts from below the
// threshold to well above it and asserts the extracted candidate set contains no
// exact duplicates at any count. A regression in the lazy-map backfill would
// show up here as a duplicate slipping through right after the map is built.
func TestDedupIsExactAcrossTheMapThreshold(t *testing.T) {
	for _, fields := range []int{1, 2, dedupMapThreshold - 1, dedupMapThreshold, dedupMapThreshold + 1, dedupMapThreshold * 2, maxCandidates + 8} {
		t.Run(fmt.Sprintf("fields=%d", fields), func(t *testing.T) {
			values := url.Values{}
			for i := 0; i < fields; i++ {
				// Deliberate duplicate payloads across distinct parameter names,
				// plus a repeated name/value pair, so both dedup arms are exercised.
				values.Add(fmt.Sprintf("p%d", i), "' OR 1=1--")
				values.Add("dup", "' OR 1=1--")
			}
			req := httptest.NewRequest(http.MethodGet, "/search?"+values.Encode(), nil)
			candidates := extractCandidatesWithAllowlist(&engine.RequestContext{Request: req}, nil)

			seen := map[string]int{}
			for _, c := range candidates {
				key := c.input.Source + "\x00" + c.input.Name + "\x00" + c.text
				seen[key]++
				if seen[key] > 1 {
					t.Fatalf("exact duplicate survived dedup at %d candidates: source=%q name=%q text=%q",
						len(candidates), c.input.Source, c.input.Name, c.text)
				}
			}
			if len(candidates) > maxCandidates {
				t.Errorf("candidate count %d exceeds the maxCandidates=%d bound", len(candidates), maxCandidates)
			}
		})
	}
}

// TestCandidateExtractionIsDeterministic guards the ordering the merge path
// depends on: report.Inputs is built by walking candidates in order, so a
// capacity change that perturbed ordering would silently reorder findings.
func TestCandidateExtractionIsDeterministic(t *testing.T) {
	build := func() []semanticCandidate {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/items?q=%27+OR+1%3D1--&page=2&sort=name",
			strings.NewReader(`{"name":"<script>alert(1)</script>","id":"../../etc/passwd","cmd":"; cat /etc/shadow"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "curl/8.0")
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
		return extractCandidatesWithAllowlist(&engine.RequestContext{Request: req}, nil)
	}

	first := build()
	if len(first) == 0 {
		t.Fatal("no candidates extracted from a request carrying query, headers, cookies and a JSON body")
	}
	for i := 0; i < 8; i++ {
		got := build()
		if len(got) != len(first) {
			t.Fatalf("candidate count varies across runs: %d then %d", len(first), len(got))
		}
		for j := range got {
			if got[j].input.Source != first[j].input.Source ||
				got[j].input.Name != first[j].input.Name ||
				got[j].text != first[j].text {
				t.Fatalf("candidate %d differs across runs: %+v vs %+v", j, first[j].input, got[j].input)
			}
		}
	}
}

// TestCandidateCapacityTracksActualWork is the regression guard for the sizing
// fix itself. Reserving the maxCandidates ceiling on every request was 44% of all
// bytes the analyzer allocated; this asserts a small request no longer pays for
// slots it cannot fill.
func TestCandidateCapacityTracksActualWork(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health?x=1", nil)
	candidates := extractCandidatesWithAllowlist(&engine.RequestContext{Request: req}, nil)
	if cap(candidates) > maxCandidates {
		t.Errorf("capacity %d exceeds the maxCandidates=%d bound", cap(candidates), maxCandidates)
	}
	// A two-field probe must not reserve anywhere near the ceiling. The bound is
	// loose on purpose: it catches a regression to unconditional maxCandidates
	// sizing without pinning an exact growth schedule.
	if cap(candidates) >= maxCandidates {
		t.Errorf("small request reserved %d slots for %d candidates; sizing regressed to the ceiling",
			cap(candidates), len(candidates))
	}
}

// TestExtractionRespectsMaxCandidatesUnderFlood confirms the cap still bounds a
// pathological request now that the initial capacity is derived from input count.
func TestExtractionRespectsMaxCandidatesUnderFlood(t *testing.T) {
	values := url.Values{}
	for i := 0; i < maxCandidates*4; i++ {
		values.Add(fmt.Sprintf("f%d", i), fmt.Sprintf("' OR %d=%d--", i, i))
	}
	req := httptest.NewRequest(http.MethodGet, "/?"+values.Encode(), nil)
	candidates := extractCandidatesWithAllowlist(&engine.RequestContext{Request: req}, nil)
	if len(candidates) > maxCandidates {
		t.Errorf("extracted %d candidates, want at most %d", len(candidates), maxCandidates)
	}
}

// TestAnalyzerStillDetectsAcrossThreshold is the end-to-end wall: a request whose
// attack payload sits past the map threshold must still be caught. Detection
// depends on every field being scanned, so a dedup bug that dropped candidates
// would surface as a miss rather than as a duplicate.
func TestAnalyzerStillDetectsAcrossThreshold(t *testing.T) {
	for _, padding := range []int{0, dedupMapThreshold, dedupMapThreshold * 3} {
		t.Run(fmt.Sprintf("padding=%d", padding), func(t *testing.T) {
			values := url.Values{}
			for i := 0; i < padding; i++ {
				values.Add(fmt.Sprintf("benign%d", i), fmt.Sprintf("value-%d", i))
			}
			values.Add("q", "1' UNION SELECT username,password FROM users--")
			req := httptest.NewRequest(http.MethodGet, "/search?"+values.Encode(), nil)

			analyzer := NewAnalyzer("block", 2)
			result, err := analyzer.Detect(context.Background(), &engine.RequestContext{Request: req})
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if result == nil {
				t.Fatalf("SQL injection missed with %d benign fields ahead of it", padding)
			}
		})
	}
}
