package semantic

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

func sqlTestRequestContext(target string, body []byte) *engine.RequestContext {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req := httptest.NewRequest(method, "http://x"+target, nil)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
}

// sqlCandidateTextsEagerReference is the pre-optimization implementation with an
// unconditional dedup map, kept verbatim as the equivalence oracle.
func sqlCandidateTextsEagerReference(reqCtx *engine.RequestContext) []string {
	seen := map[string]struct{}{}
	candidates := make([]string, 0, 8)
	addRaw := func(text string) {
		if len(candidates) >= maxSQLCandidateTexts {
			return
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		if _, ok := seen[text]; ok {
			return
		}
		seen[text] = struct{}{}
		candidates = append(candidates, text)
	}
	addVariants := func(text string) {
		for _, segment := range sqlCandidateSegments(text) {
			addRaw(segment)
			for _, decoded := range decoder.DecodeAll(segment) {
				addRaw(decoded.Text)
				if b64, ok := decoder.TryBase64(strings.TrimSpace(decoded.Text)); ok {
					addRaw(b64)
				}
			}
		}
	}

	addVariants(requestText(reqCtx))
	if reqCtx == nil || reqCtx.Request == nil {
		return candidates
	}
	for _, values := range reqCtx.Request.URL.Query() {
		for _, value := range values {
			addVariants(value)
		}
	}
	contentType := strings.ToLower(reqCtx.Request.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(reqCtx.DecodedBody)); err == nil {
			for _, items := range values {
				for _, value := range items {
					addVariants(value)
				}
			}
		}
	}
	return candidates
}

// TestSQLCandidateDedupMatchesEagerMapReference pins that the lazy dedup map
// yields byte-identical candidate lists to the eager map it replaced, on both
// sides of dedupMapThreshold. The map is a memory optimization only; a
// divergence here would silently change which payloads the SQL detector sees.
func TestSQLCandidateDedupMatchesEagerMapReference(t *testing.T) {
	cases := []struct {
		name string
		path string
		body []byte
	}{
		{"single field", "/q?a=1", nil},
		{"repeated identical values", "/q?a=x&b=x&c=x&d=x", nil},
		{"below threshold", "/q?" + manyDistinct(5), nil},
		{"at threshold boundary", "/q?" + manyDistinct(12), nil},
		{"above threshold", "/q?" + manyDistinct(30), nil},
		{"encoded duplicates", "/q?a=%27%20OR%201%3D1--&b=%27%20OR%201%3D1--", nil},
		{"sqli payload", "/q?id=1%27%20UNION%20SELECT%20password--", nil},
		{"form body with duplicates", "/q?a=1", []byte("u=admin%27--&p=x&u2=admin%27--")},
		{"form body many fields", "/q?a=1", []byte(manyDistinct(20))},
		{"base64 payload", "/q?d=c2VsZWN0ICogZnJvbSB1c2Vycw==", nil},
		{"long value segmented", "/q?big=" + strings.Repeat("A", 9000), nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sqlCandidateTexts(sqlTestRequestContext(tc.path, tc.body))
			want := sqlCandidateTextsEagerReference(sqlTestRequestContext(tc.path, tc.body))

			// Compared as sets: candidate order already depends on Go's randomized
			// map iteration over URL.Query(), both before and after this change, so
			// sequence equality is not a property either implementation has.
			if len(got) != len(want) {
				t.Fatalf("candidate count = %d, eager reference = %d\ngot:  %q\nwant: %q", len(got), len(want), got, want)
			}
			gotSet := map[string]int{}
			for _, candidate := range got {
				gotSet[candidate]++
			}
			for _, candidate := range want {
				gotSet[candidate]--
			}
			for candidate, delta := range gotSet {
				if delta != 0 {
					t.Fatalf("candidate %q multiplicity differs from eager reference by %d", candidate, delta)
				}
			}
		})
	}
}

// TestSQLCandidateDedupIsExactAcrossTheMapThreshold checks the invariant
// directly: no candidate may repeat, whichever path built the list.
func TestSQLCandidateDedupIsExactAcrossTheMapThreshold(t *testing.T) {
	for _, fields := range []int{1, 2, 5, 11, 12, 13, 24, 40} {
		t.Run(fmt.Sprintf("fields=%d", fields), func(t *testing.T) {
			query := url.Values{}
			for i := 0; i < fields; i++ {
				query.Set(fmt.Sprintf("f%d", i), fmt.Sprintf("value-%d' OR 1=1--", i))
				query.Add(fmt.Sprintf("dup%d", i), "shared-duplicate-value")
			}

			got := sqlCandidateTexts(sqlTestRequestContext("/search?"+query.Encode(), nil))

			counts := map[string]int{}
			for _, candidate := range got {
				counts[candidate]++
			}
			for candidate, count := range counts {
				if count != 1 {
					t.Fatalf("candidate %q appeared %d times; dedup must stay exact", candidate, count)
				}
			}
			if len(got) == 0 {
				t.Fatalf("expected candidates for %d fields, got none", fields)
			}
		})
	}
}

func manyDistinct(n int) string {
	query := url.Values{}
	for i := 0; i < n; i++ {
		query.Set(fmt.Sprintf("k%d", i), fmt.Sprintf("distinct-value-%d", i))
	}
	return query.Encode()
}

func BenchmarkSQLCandidateTexts(b *testing.B) {
	reqCtx := sqlTestRequestContext("/search?id=1%27%20OR%201%3D1--&page=2&sort=name", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = sqlCandidateTexts(reqCtx)
	}
}
