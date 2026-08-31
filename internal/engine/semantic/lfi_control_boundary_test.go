package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestLFIControlBoundaryDoesNotJoinDocumentationCommand(t *testing.T) {
	body := `{"content":"Reference: c%00at /etc/passwd is a command example."}`
	req := httptest.NewRequest(http.MethodPost, "http://x/docs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", 5, "lfi").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Detected {
		t.Fatalf("internal NUL boundary joined a documentation command: %+v", result)
	}
}

func TestLFIControlBoundaryKeepsPathSuffixRecall(t *testing.T) {
	for _, target := range []string{
		"/download?file=%2Fetc%2Fpasswd%00.jpg",
		"/download?file=../../etc/passwd%00",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://x"+target, nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "lfi").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != "lfi" {
				t.Fatalf("null-byte path suffix was missed: %+v", result)
			}
		})
	}
}

func TestStandaloneLFIControlBoundaryKeepsPathSuffixRecall(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/download?file=../../etc/passwd%00.jpg", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewLFIDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "lfi" {
		t.Fatalf("standalone null-byte path suffix was missed: %+v", result)
	}
}
