package semantic

import (
	"context"
	"mime"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestOverlongPathCategoryHintsUseFoldedView(t *testing.T) {
	// Exercise category admission directly: unrelated punctuation must not
	// exclude LFI before its path decoder can inspect the same value.
	path := strings.Repeat("\xc0\xae\xc0\xae\xc0\xaf", 3) + "app/settings.yml"
	for _, prefix := range []string{"", strings.Repeat("folder/", 45)} {
		for _, suffix := range []string{"$", "--"} {
			value := prefix + path + suffix
			got := guessCategoriesForSource(value, "file", "query")
			if !slices.Contains(got, "lfi") {
				t.Errorf("length=%d suffix=%q: LFI omitted from categories %v", len(value), suffix, got)
			}
		}
	}
}

func TestContentTypeParameterRemainsAnInspectableInput(t *testing.T) {
	const contentType = `application/json; charset="diagnostic-marker"`
	if _, _, err := mime.ParseMediaType(contentType); err != nil {
		t.Fatalf("fixture is not a legal media type: %v", err)
	}
	for _, path := range []string{"/upload", "/health"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
		req.Header.Set("Content-Type", contentType)
		reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
		found := false
		for _, candidate := range extractCandidates(reqCtx) {
			if candidate.input.Source == "header" && strings.EqualFold(candidate.input.Name, "Content-Type") && candidate.input.Raw == contentType {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: Content-Type parameters were excluded from semantic inputs", path)
		}
	}
}

func TestPlainBodyMediaTypesKeepFastInputPath(t *testing.T) {
	for _, contentType := range knownBodyMediaTypes {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
		req.Header.Set("Content-Type", contentType)
		if got := extractCandidates(&engine.RequestContext{Request: req}); len(got) != 0 {
			t.Errorf("%s: plain media type consumed %d candidate slots", contentType, len(got))
		}
	}
}

func TestOrdinaryContentTypesRemainClean(t *testing.T) {
	for _, contentType := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/vnd.api+json",
		"application/ld+json",
		"text/plain; charset=UTF-8",
		"application/x-www-form-urlencoded; charset=UTF-8",
		`text/plain; name="quarterly report.txt"`,
	} {
		t.Run(contentType, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test/health", nil)
			req.Header.Set("Content-Type", contentType)
			reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
			got, err := NewAnalyzer("block", 3).Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatalf("detect: %v", err)
			}
			if got != nil && got.Detected {
				t.Fatalf("ordinary Content-Type produced a detection: %+v", got)
			}
		})
	}
}

func TestPathAllowlistRequiresEveryMatrixRoutingInterpretation(t *testing.T) {
	for _, target := range []string{
		"/health/;p/../private",
		"/health/%3bp/../private",
		"/health/a;p/../../private",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test"+target, nil)
			reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
			a := NewAnalyzer("block", 3)
			a.SetAllowlists([]string{"/health"}, nil)
			if _, err := a.Detect(context.Background(), reqCtx); err != nil {
				t.Fatal(err)
			}
			if reqCtx.Metadata["semantic_skipped"] != nil {
				t.Fatal("matrix routing interpretation outside the allowlist skipped analysis")
			}
		})
	}
}

func TestPathAllowlistKeepsNonMatrixNormalization(t *testing.T) {
	for _, target := range []string{
		"/outside/../health",
		"//health",
		"/outside/%2e%2e/health",
		"/health/a;p/../status",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test"+target, nil)
			reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
			a := NewAnalyzer("block", 3)
			a.SetAllowlists([]string{"/health"}, nil)
			if _, err := a.Detect(context.Background(), reqCtx); err != nil {
				t.Fatal(err)
			}
			if reqCtx.Metadata["semantic_skipped"] != "path_allowlist" {
				t.Fatal("existing allowlisted path no longer skipped analysis")
			}
		})
	}
}
