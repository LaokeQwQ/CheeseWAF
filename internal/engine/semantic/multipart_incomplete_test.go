package semantic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAnalyzerMultipartIncompleteCleanReturnsTypedSignal(t *testing.T) {
	truncatedContentType, truncatedBody := multipartValuesFixture(t, 1, func(int) string { return "ordinary" })
	if len(truncatedBody) < 4 {
		t.Fatal("multipart fixture unexpectedly short")
	}
	truncatedBody = truncatedBody[:len(truncatedBody)-4]
	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{
			name:        "truncated",
			contentType: truncatedContentType,
			body:        truncatedBody,
		},
		{
			name:        "malformed",
			contentType: "multipart/form-data; boundary=malformed-clean-boundary",
			body: []byte("--malformed-clean-boundary\r\n" +
				"Content-Disposition: form-data; name=broken\r\n" +
				"not-a-header\r\n\r\nordinary\r\n" +
				"--malformed-clean-boundary--\r\n"),
		},
	}

	contentType, body := multipartValuesFixture(t, maxMultipartInputs+1, func(int) string { return "ordinary" })
	tests = append(tests, struct {
		name        string
		contentType string
		body        []byte
	}{name: "over input limit", contentType: contentType, body: body})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			reqCtx := &engine.RequestContext{Request: req, DecodedBody: tc.body, Metadata: map[string]any{}}

			result, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
			if result != nil && result.Detected {
				t.Fatalf("clean incomplete multipart was detected: %+v", result)
			}
			if !errors.Is(err, ErrSemanticInputIncomplete) {
				t.Fatalf("Detect error = %v, want ErrSemanticInputIncomplete", err)
			}
			var signal interface {
				error
				AnalysisIncomplete() bool
				IncompleteReason() string
			}
			if !errors.As(err, &signal) || !signal.AnalysisIncomplete() || signal.IncompleteReason() != multipartCoverageIncompleteReason {
				t.Fatalf("Detect error does not expose typed incomplete signal: %#v", err)
			}
			if got, _ := reqCtx.Metadata["semantic_input_incomplete"].(bool); !got {
				t.Fatalf("semantic_input_incomplete missing: %#v", reqCtx.Metadata)
			}
			if got, _ := reqCtx.Metadata["semantic_analysis_incomplete"].(bool); !got {
				t.Fatalf("semantic_analysis_incomplete missing: %#v", reqCtx.Metadata)
			}
			if got, _ := reqCtx.Metadata["semantic_input_incomplete_reason"].(string); got != multipartCoverageIncompleteReason {
				t.Fatalf("semantic input reason missing: %#v", reqCtx.Metadata)
			}
			if got, _ := reqCtx.Metadata["semantic_analysis_incomplete_reason"].(string); got != multipartCoverageIncompleteReason {
				t.Fatalf("semantic analysis reason missing: %#v", reqCtx.Metadata)
			}
		})
	}
}

func TestAnalyzerMultipartIncompleteAttackKeepsDetectionPriority(t *testing.T) {
	contentType, body := multipartValuesFixture(t, maxMultipartInputs+1, func(i int) string {
		if i == 0 {
			return "; whoami"
		}
		return "ordinary"
	})
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	reqCtx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}

	result, err := NewAnalyzer("block", 5, "rce").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatalf("explicit attack was replaced by incomplete error: %v", err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock || result.Category != "rce" {
		t.Fatalf("explicit attack lost detection priority: %+v", result)
	}
	if got, _ := reqCtx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatalf("attack should retain incomplete audit metadata: %#v", reqCtx.Metadata)
	}
}

func multipartValuesFixture(t *testing.T, count int, value func(int) string) (string, []byte) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < count; i++ {
		part, err := writer.CreateFormField(fmt.Sprintf("field_%03d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(value(i))); err != nil {
			t.Fatal(err)
		}
	}
	contentType := writer.FormDataContentType()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return contentType, append([]byte(nil), body.Bytes()...)
}
