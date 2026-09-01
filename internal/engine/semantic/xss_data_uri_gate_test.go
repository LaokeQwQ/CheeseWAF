package semantic

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestXSSDataURLInURLField(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script>"))
	target := "/redirect?target=" + url.QueryEscape("data:text/html;base64,"+encoded)
	a := NewAnalyzer("block", 2, "xss")
	got := detectOnTarget(t, a, "GET", target, "", "")
	if got == nil || !got.Detected || got.Category != "xss" {
		t.Fatalf("expected executable data URI in URL field to be detected, got %+v", got)
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := NewXSSDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if standalone == nil || !standalone.Detected || standalone.Category != "xss" {
		t.Fatalf("standalone detector missed executable data URI, got %+v", standalone)
	}
}

func TestXSSDataURLPathSurface(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("<svg onload=alert(1)>"))
	target := "/data:text/html;base64," + encoded
	got := detectOnTarget(t, NewAnalyzer("block", 2, "xss"), "GET", target, "", "")
	if got == nil || !got.Detected || got.Category != "xss" {
		t.Fatalf("expected executable data URI path to be detected, got %+v", got)
	}
}

func TestXSSDataURLFieldGateKeepsBenignValuesClean(t *testing.T) {
	encodedHTML := base64.StdEncoding.EncodeToString([]byte("<p>plain page</p>"))
	encodedText := base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script>"))
	cases := []struct {
		name, field, value string
	}{
		{"non-url-field", "comment", "data:text/html;base64," + encodedText},
		{"plain-html", "target", "data:text/html;base64," + encodedHTML},
		{"plain-text-media", "target", "data:text/plain;base64," + encodedText},
		{"math-text", "comment", "The data:text/html;base64 URI is documented, not executed."},
	}
	a := NewAnalyzer("block", 2, "xss")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "/docs?" + tc.field + "=" + url.QueryEscape(tc.value)
			got := detectOnTarget(t, a, "GET", target, "", "")
			if got != nil && got.Detected && got.Category == "xss" {
				t.Fatalf("benign/non-sink data URI triggered XSS: %+v", got)
			}
		})
	}

	// The field-name matcher must remain token-exact: urlish is ordinary data.
	candidate := semanticCandidate{
		input: InputPoint{Source: "query", Name: "urlish"},
		text:  "data:text/html;base64," + encodedText,
	}
	if xssDataURLFieldContext(candidate) {
		t.Fatal("urlish field was treated as an executable URL sink")
	}
}
