package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestReviewUnicodeEvidenceWindowUsesOriginalByteOffsets(t *testing.T) {
	for _, prefix := range []string{strings.Repeat("Ⱥ", 500), strings.Repeat("Ⱥ", 500) + "😀"} {
		text := prefix + " UNION SELECT 1"
		window := evidenceWindow(text, []string{"union select"})
		if !strings.Contains(window, "UNION SELECT 1") || !utf8.ValidString(window) {
			t.Fatalf("evidence window lost attack or split UTF-8: %q", window)
		}
	}
}

func TestReviewStandaloneSSIWithExpandingUnicodePrefix(t *testing.T) {
	body := strings.Repeat("Ⱥ", 500) + `<!--#EXEC cmd="id"-->`
	req := httptest.NewRequest(http.MethodPost, "/render", strings.NewReader(body))
	result, err := NewLFIDetector("block").Detect(context.Background(), &engine.RequestContext{Request: req, DecodedBody: []byte(body)})
	if err != nil || result == nil || !result.Detected {
		t.Fatalf("Unicode-prefixed SSI was missed: result=%+v err=%v", result, err)
	}
}

func TestReviewSingleReportMarkerDoesNotSuppressRawAttack(t *testing.T) {
	for _, marker := range []string{"cve-2021-1234", "wooyun-2021-1234", "exploit-db", "security advisory", "att&ck", "kcon", "security team"} {
		t.Run(marker, func(t *testing.T) {
			body := marker + "\n" + strings.Repeat("a", documentScaleThreshold) + "\n;cat /etc/passwd"
			if vulnerabilityReportContext(body) {
				t.Fatal("single attacker-controlled marker is not a structured vulnerability report")
			}
			result := detectOnTarget(t, NewAnalyzer("block", 2, "rce"), http.MethodPost, "/render", "text/plain", body)
			if result == nil || !result.Detected {
				t.Fatalf("single report marker hid shell command: %+v", result)
			}
		})
	}
}

func TestReviewStructuredFieldsDoNotTrustDocumentationMarkers(t *testing.T) {
	for _, tc := range []struct{ category, payload string }{
		{"sqli", "1' OR 1=1-- cve-2021-1234"},
		{"rce", ";cat /etc/passwd #cve-2021-1234"},
		{"lfi", "../../../../etc/passwd cve-2021-1234"},
		{"xss", "<script>alert(1)</script> cve-2021-1234"},
	} {
		for _, source := range []string{"query", "body.form", "body.json", "body.multipart", "cookie", "header", "uri"} {
			t.Run(tc.category+"/"+source, func(t *testing.T) {
				text := tc.payload + "\n" + strings.Repeat("Documented example for security training. ", 12)
				candidate := semanticCandidate{input: InputPoint{Source: source, Name: "value"}, text: text}
				if _, ok := analyzeSyntaxAndSemantics(tc.category, candidate); !ok {
					t.Fatalf("documentation markers suppressed %s in %s", tc.category, source)
				}
			})
		}
	}
}

func TestReviewMultipartFileContentHasDocumentSource(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("upload", "article.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("A document uploaded as a file.")); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("content", "An ordinary form parameter."); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	inputs := multipartInputs(body.Bytes(), writer.Boundary())
	for _, input := range inputs {
		allowed := documentSourceAllowed(input.Source)
		if input.Name == "upload" && !allowed {
			t.Fatalf("actual file content has no document provenance: %+v", input)
		}
		if input.Name != "upload" && allowed {
			t.Fatalf("filename or form parameter gained document provenance: %+v", input)
		}
	}
}

func TestReviewJSONStreamStopsAtDepthBudget(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(strings.Repeat("[", 1<<20)))
	var status traversalStatus
	collector := newJSONInputCollector(maxCandidates, &status)
	err := streamJSONValue(decoder, "body.json", "", 0, &collector)
	if err == nil || !status.omitted || status.reason != jsonDepthLimitIncompleteReason {
		t.Fatalf("deep JSON did not stop with depth omission: status=%+v err=%v", status, err)
	}
	if consumed := decoder.InputOffset(); consumed > maxJSONDepth+1 {
		t.Fatalf("depth budget still consumed %d bytes instead of stopping at the nesting bound", consumed)
	}
}

func TestReviewDeepMalformedJSONRemainsIncomplete(t *testing.T) {
	for _, prefix := range []string{"[", `{"a":`, `[{"a":`} {
		for _, size := range []int{128, 1 << 20} {
			t.Run(fmt.Sprintf("%s/%d", prefix, size), func(t *testing.T) {
				body := strings.Repeat(prefix, size/len(prefix))
				req := httptest.NewRequest(http.MethodPost, "/json", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				ctx := &engine.RequestContext{Request: req, DecodedBody: []byte(body)}
				result, err := NewAnalyzer("block", 2).Detect(context.Background(), ctx)
				if result == nil && !errors.Is(err, ErrSemanticInputIncomplete) {
					t.Fatalf("deep malformed JSON became a complete pass: result=%+v err=%v metadata=%+v", result, err, ctx.Metadata)
				}
			})
		}
	}
}

func TestReviewOversizedRequestFieldsReturnIncomplete(t *testing.T) {
	for _, source := range []string{"query", "header", "cookie", "path"} {
		t.Run(source, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			large := strings.Repeat("a", maxInputRawBytes+1)
			switch source {
			case "query":
				req.URL.RawQuery = "q=" + large
			case "header":
				req.Header.Set("X-Input", large)
			case "cookie":
				req.AddCookie(&http.Cookie{Name: "input", Value: large})
			case "path":
				req.URL.Path = "/" + large
			}
			ctx := &engine.RequestContext{Request: req}
			result, err := NewAnalyzer("block", 2).Detect(context.Background(), ctx)
			if result != nil || !errors.Is(err, ErrSemanticInputIncomplete) {
				t.Fatalf("oversized %s became a complete pass: result=%+v err=%v", source, result, err)
			}
		})
	}
}

func TestReviewPathAllowlistUsesNormalizedPath(t *testing.T) {
	for _, path := range []string{"/static/../admin", "/static/%2e%2e/admin", "/static/%252e%252e/admin"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path+"?q="+url.QueryEscape("1' OR 1=1--"), nil)
			ctx := &engine.RequestContext{Request: req}
			analyzer := NewAnalyzer("block", 2, "sqli")
			analyzer.SetAllowlists([]string{"/static"}, nil)
			result, err := analyzer.Detect(context.Background(), ctx)
			if err != nil || result == nil || !result.Detected || ctx.Metadata["semantic_skipped"] != nil {
				t.Fatalf("path normalization bypassed semantic analysis: result=%+v err=%v metadata=%+v", result, err, ctx.Metadata)
			}
		})
	}
}

func TestReviewUnicodeCandidatesAcrossScanModes(t *testing.T) {
	analyzer := NewAnalyzer("block", 2, "sqli")
	for _, count := range []int{1, 3, parallelCandidateThreshold, maxCandidates} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			candidates := make([]semanticCandidate, count)
			for i := range candidates {
				candidates[i] = semanticCandidate{
					input: InputPoint{Source: "query", Name: fmt.Sprintf("p%d", i)},
					text:  strings.Repeat("Ⱥ", 500) + " UNION SELECT 1",
				}
			}
			report, _, haveBest, incomplete := analyzer.analyzeAllCandidates(context.Background(), candidates)
			if incomplete || !haveBest || len(report.Inputs) != len(candidates) {
				t.Fatalf("Unicode attack was not fully analyzed: incomplete=%v haveBest=%v inputs=%d", incomplete, haveBest, len(report.Inputs))
			}
		})
	}
}
