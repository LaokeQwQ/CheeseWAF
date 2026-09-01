package semantic

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

// candidateFingerprint keeps the assertions below independent of decoder
// variant slices while still pinning the order consumed by the candidate budget.
func candidateFingerprint(candidates []semanticCandidate) string {
	var b strings.Builder
	for _, candidate := range candidates {
		fmt.Fprintf(&b, "%s\x00%s\x00%s\n", candidate.input.Source, candidate.input.Name, candidate.text)
	}
	return b.String()
}

func TestFormCandidateExtractionDeterministicUnderBudget(t *testing.T) {
	var body strings.Builder
	for i := 0; i < maxCandidates+16; i++ {
		if i > 0 {
			body.WriteByte('&')
		}
		fmt.Fprintf(&body, "field_%03d=ordinary", i)
	}
	body.WriteString("&zz_attack=%27%20OR%201%3D1%20--")
	bodyBytes := []byte(body.String())

	build := func() []semanticCandidate {
		req := httptest.NewRequest(http.MethodPost, "/submit", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return extractCandidatesWithAllowlist(&engine.RequestContext{
			Request:     req,
			DecodedBody: bodyBytes,
			Metadata:    map[string]any{},
		}, nil)
	}

	want := candidateFingerprint(build())
	if !strings.Contains(want, "body.form\x00zz_attack\x00' OR 1=1 --") {
		t.Fatal("late form attack was not retained by candidate budget")
	}
	for i := 0; i < 100; i++ {
		if got := candidateFingerprint(build()); got != want {
			t.Fatalf("form candidate order changed on run %d", i)
		}
	}
}

func TestJSONDecoderFallbackDeterministicUnderBudget(t *testing.T) {
	var body strings.Builder
	body.WriteByte('{')
	for i := 0; i < maxCandidates+16; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"field_%03d":"ordinary"`, i)
	}
	// The escaped value forces flattenJSONInputs through the decoder fallback;
	// keep the attack lexically last so map traversal can affect the cap.
	body.WriteString(`,"zz_attack":"\u003b whoami"}`)
	bodyBytes := []byte(body.String())

	build := func() []semanticCandidate {
		req := httptest.NewRequest(http.MethodPost, "/submit", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		return extractCandidatesWithAllowlist(&engine.RequestContext{
			Request:     req,
			DecodedBody: bodyBytes,
			Metadata:    map[string]any{},
		}, nil)
	}

	want := candidateFingerprint(build())
	if !strings.Contains(want, "body.json\x00zz_attack\x00; whoami") {
		t.Fatal("late escaped JSON attack was not retained by candidate budget")
	}
	for i := 0; i < 100; i++ {
		if got := candidateFingerprint(build()); got != want {
			t.Fatalf("JSON decoder-fallback candidate order changed on run %d", i)
		}
	}
}

func TestMultipartTruncatedTailKeepsEarlierAttack(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("payload")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("; whoami")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	full := body.Bytes()
	if len(full) < 8 {
		t.Fatal("multipart fixture unexpectedly short")
	}
	// Drop the closing delimiter. NextPart must report an error after yielding
	// the first part; the already-observed attack must not be discarded.
	truncated := full[:len(full)-4]
	boundary := boundaryFromContentType(writer.FormDataContentType())
	inputs := multipartInputs(truncated, boundary)
	found := false
	for _, input := range inputs {
		if input.Name == "payload" && strings.Contains(input.Raw, "; whoami") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("truncated multipart tail discarded an attack from an earlier part")
	}
}

func TestMultipartTruncationSurfacesIncompleteMetadata(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormField("payload")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("ordinary")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	full := body.Bytes()
	truncated := full[:len(full)-4]
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(truncated))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	ctx := &engine.RequestContext{Request: req, DecodedBody: truncated, Metadata: map[string]any{}}
	_ = extractCandidatesWithAllowlist(ctx, nil)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatalf("truncated multipart body was not marked incomplete: %#v", ctx.Metadata)
	}
}

func TestMultipartMalformedPartSurfacesIncompleteMetadata(t *testing.T) {
	const boundary = "candidate-boundary"
	// The first part has a malformed header block. A valid-looking attack follows,
	// but the parser must expose the lost coverage instead of presenting a clean
	// candidate set as complete.
	body := []byte("--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=broken\r\n" +
		"not-a-header\r\n\r\nordinary\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=payload\r\n\r\n; whoami\r\n" +
		"--" + boundary + "--\r\n")
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	ctx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
	_ = extractCandidatesWithAllowlist(ctx, nil)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatalf("malformed multipart part was not marked incomplete: %#v", ctx.Metadata)
	}
	points, _ := bodyInputsWithStatus(req, body)
	if len(points) == 0 || points[0].Source != "body.raw" || !strings.Contains(points[0].Raw, "; whoami") {
		t.Fatalf("incomplete multipart body lost raw coverage: %+v", points)
	}
}

func TestMultipartMissingBoundarySurfacesIncompleteMetadata(t *testing.T) {
	body := []byte("--missing-boundary\r\nnot reliably parseable")
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data")
	ctx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
	_ = extractCandidatesWithAllowlist(ctx, nil)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatalf("multipart body without boundary was not marked incomplete: %#v", ctx.Metadata)
	}
}

func TestMultipartMalformedBoundaryParameterSurfacesIncompleteMetadata(t *testing.T) {
	body := []byte("payload=; whoami")
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	// The parameter has no value, so mime.ParseMediaType rejects it.
	req.Header.Set("Content-Type", "multipart/form-data; boundary")
	ctx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
	_ = extractCandidatesWithAllowlist(ctx, nil)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatalf("multipart body with malformed boundary parameter was not marked incomplete: %#v", ctx.Metadata)
	}
}

func TestMultipartLookalikeMediaTypeIsNotMarkedIncomplete(t *testing.T) {
	body := []byte("ordinary body")
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-datax")
	ctx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
	_ = extractCandidatesWithAllowlist(ctx, nil)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); got {
		t.Fatalf("lookalike media type incorrectly marked incomplete: %#v", ctx.Metadata)
	}
}

func TestMultipartExactInputCapIsComplete(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < maxMultipartInputs; i++ {
		part, err := writer.CreateFormField(fmt.Sprintf("field_%03d", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte("ordinary")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	boundary := boundaryFromContentType(writer.FormDataContentType())
	inputs, incomplete := multipartInputsWithStatus(body.Bytes(), boundary)
	if len(inputs) != maxMultipartInputs {
		t.Fatalf("got %d inputs, want exact cap %d", len(inputs), maxMultipartInputs)
	}
	if incomplete {
		t.Fatal("well-formed body ending exactly at multipart cap marked incomplete")
	}
}

func TestMultipartEmptyPartFloodIsBoundedAndMarkedIncomplete(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i := 0; i < maxMultipartInputs+1; i++ {
		if _, err := writer.CreateFormField(fmt.Sprintf("empty_%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	boundary := boundaryFromContentType(writer.FormDataContentType())
	inputs, incomplete := multipartInputsWithStatus(body.Bytes(), boundary)
	if len(inputs) != 0 {
		t.Fatalf("empty-part flood produced %d inputs, want 0", len(inputs))
	}
	if !incomplete {
		t.Fatal("empty-part flood beyond parts cap was not marked incomplete")
	}
}
