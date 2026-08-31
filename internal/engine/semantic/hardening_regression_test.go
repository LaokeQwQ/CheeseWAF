package semantic

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAnalyzerRawBodyDetectsAttackPastFieldPrefix(t *testing.T) {
	body := strings.Repeat("a", maxInputRawBytes+1024) + "; whoami"
	req := httptestRequestWithBody(t, "application/octet-stream", []byte(body))
	assertAnalyzerCategory(t, req, "rce")
}

func TestAnalyzerMultipartDetectsAttackPastFieldPrefix(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("payload")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(strings.Repeat("a", maxInputRawBytes+1024) + "; whoami")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptestRequestWithBody(t, writer.FormDataContentType(), body.Bytes())
	assertAnalyzerCategory(t, req, "rce")
}

// maxMultipartInputs is the only thing bounding how many inputs one
// attacker-controlled multipart body can contribute. Pin both ends: a body with
// far more parts than the cap must be truncated to it, and the cap must still
// admit ordinary uploads.
func TestMultipartInputsCapsPartCount(t *testing.T) {
	const parts = 512
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < parts; i++ {
		field, err := writer.CreateFormField(fmt.Sprintf("field_%03d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := field.Write([]byte("ordinary")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	contentType := writer.FormDataContentType()
	boundary := boundaryFromContentType(contentType)
	if boundary == "" {
		t.Fatalf("no boundary in %q", contentType)
	}
	inputs := multipartInputs(body.Bytes(), boundary)
	if len(inputs) == 0 {
		t.Fatal("multipartInputs returned nothing for a well-formed body")
	}
	if len(inputs) > maxMultipartInputs {
		t.Fatalf("multipartInputs returned %d inputs for %d parts, want <= %d", len(inputs), parts, maxMultipartInputs)
	}
	// The cap must be what stopped the walk, not the end of the body.
	if len(inputs) < maxMultipartInputs {
		t.Fatalf("multipartInputs stopped at %d inputs, want the cap %d to bind", len(inputs), maxMultipartInputs)
	}
}

func TestAnalyzerBodyCannotBeStarvedByQueryCandidates(t *testing.T) {
	query := make(url.Values, maxCandidates)
	for i := 0; i < maxCandidates; i++ {
		query.Set(fmt.Sprintf("field_%02d", i), "ordinary")
	}
	req, err := http.NewRequest(http.MethodPost, "/submit?"+query.Encode(), strings.NewReader(`{"cmd":"; whoami"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	assertAnalyzerCategory(t, req, "rce")
}

func TestAnalyzerLateJSONFieldCannotEscapeCandidateBudget(t *testing.T) {
	var body strings.Builder
	body.WriteByte('{')
	for i := 0; i < maxCandidates; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"field_%02d":"ordinary"`, i)
	}
	body.WriteString(`,"cmd":"; whoami"}`)
	req := httptestRequestWithBody(t, "application/json", []byte(body.String()))
	assertAnalyzerCategory(t, req, "rce")
}

func TestAnalyzerAllowlistedFieldsCannotConsumeCandidateBudget(t *testing.T) {
	query := url.Values{}
	for i := 0; i < maxCandidates*2; i++ {
		query.Add("noise", fmt.Sprintf("ordinary-%03d", i))
	}
	req, err := http.NewRequest(http.MethodPost, "/submit?"+query.Encode(), strings.NewReader(`{"cmd":"; whoami"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	analyzer := NewAnalyzer("block", 2, "rce")
	analyzer.SetAllowlists(nil, []string{"noise"})
	result, err := analyzer.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "rce" {
		t.Fatalf("allowlisted padding hid body attack: %+v", result)
	}
}

func TestAnalyzerSuspiciousHeaderSurvivesCandidateCrowding(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCandidates*4; i++ {
		req.Header.Set(fmt.Sprintf("X-Ordinary-%03d", i), "ordinary")
	}
	req.Header.Set("X-Command", "; whoami")
	assertAnalyzerCategory(t, req, "rce")
}

func TestAnalyzerOversizedRawBodyDetectsAttackInMiddle(t *testing.T) {
	body := strings.Repeat("a", maxInputRawBytes*2) + "; whoami " + strings.Repeat("b", maxInputRawBytes*2)
	if !rawCoverageSignal.MatchString("; whoami") {
		t.Fatal("raw coverage prefilter does not recognize the RCE shape")
	}
	sample := clipRawBytes([]byte(body))
	if !strings.Contains(sample, "; whoami") {
		t.Fatal("bounded raw sample dropped the middle attack")
	}
	if hits := NewAnalyzer("block", 2, "rce").analyzeCandidate(semanticCandidate{
		input: InputPoint{Source: "body.raw", Name: "body", Raw: sample, Layers: rawLayersOnly},
		text:  sample,
	}); len(hits) == 0 {
		t.Fatal("bounded middle sample did not reach the RCE detector")
	}
	req := httptestRequestWithBody(t, "application/octet-stream", []byte(body))
	assertAnalyzerCategory(t, req, "rce")
}

func httptestRequestWithBody(t *testing.T, contentType string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	return req
}

func assertAnalyzerCategory(t *testing.T, req *http.Request, category string) {
	t.Helper()
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", 2, category).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != category {
		t.Fatalf("expected %s detection, got %+v", category, result)
	}
}
