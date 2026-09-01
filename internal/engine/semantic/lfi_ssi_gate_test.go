package semantic

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestServerSideIncludeWithoutSensitivePathIsDetected(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{name: "exec-command", body: `<!--#exec cmd="id"-->`},
		{name: "echo-variable", body: `<!--#echo var="DOCUMENT_NAME"-->`},
		{name: "split-opener", body: `<!- -#include file="config.ini" - ->`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), http.MethodPost,
				"/render", "text/plain", tc.body)
			if got == nil || !got.Detected || got.Category != "lfi" {
				t.Fatalf("expected SSI LFI detection, got %+v", got)
			}
		})
	}
}

func TestLongServerSideIncludeSurvivesPrefilter(t *testing.T) {
	body := strings.Repeat("ordinary-template-text ", 18) + `<!--#exec cmd="id"-->`
	got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), http.MethodPost,
		"/render", "text/plain", body)
	if got == nil || !got.Detected || got.Category != "lfi" {
		t.Fatalf("long SSI directive was dropped by the prefilter: %+v", got)
	}
}

func TestServerSideIncludeNotHiddenByDistantDocumentationPrefix(t *testing.T) {
	body := "Security advisory background and remediation notes.\n" +
		strings.Repeat("padding keeps the later request value outside the prose window. ", 5) +
		`<!--#exec cmd="id"-->`
	got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), http.MethodPost,
		"/render", "text/plain", body)
	if got == nil || !got.Detected || got.Category != "lfi" {
		t.Fatalf("SSI payload after a distant documentation prefix was suppressed: %+v", got)
	}
}

func TestStandaloneServerSideIncludeDetectionAndDocumentationGate(t *testing.T) {
	attack := `<!--#exec cmd="id"-->`
	req, err := http.NewRequest(http.MethodPost, "http://x/render", strings.NewReader(attack))
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewLFIDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "lfi" {
		t.Fatalf("standalone SSI directive was missed: %+v", result)
	}

	doc := "Documentation example: the following SSI directive is shown for defenders, not executed: " +
		`<!--#exec cmd="id"-->` + "\n" +
		strings.Repeat("This paragraph explains server-side include syntax and safe testing. ", 5)
	docReq, err := http.NewRequest(http.MethodPost, "http://x/docs", strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	docCtx, err := engine.NewRequestContext(docReq, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err = NewLFIDetector("block").Detect(context.Background(), docCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil && result.Detected {
		t.Fatalf("SSI documentation example was flagged: %+v", result)
	}
}

func TestServerSideIncludeDocumentationStaysClean(t *testing.T) {
	body := "Documentation example: the following SSI directive is shown for defenders, not executed: " +
		`<!--#exec cmd="id"-->` + "\n" +
		strings.Repeat("This paragraph explains server-side include syntax and safe testing. ", 5)
	got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), http.MethodPost,
		"/docs", "text/plain", body)
	if got != nil && got.Detected {
		t.Fatalf("SSI documentation example was flagged by analyzer: %+v", got)
	}
}

func TestServerSideIncludeInEncodedQueryIsDetected(t *testing.T) {
	payload := `<!--#exec cmd="id"-->`
	target := "/render?template=" + url.QueryEscape(payload)
	got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), http.MethodGet, target, "", "")
	if got == nil || !got.Detected || got.Category != "lfi" {
		t.Fatalf("encoded SSI query payload was missed: %+v", got)
	}
}
