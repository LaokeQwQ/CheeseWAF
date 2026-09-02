package semantic

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestJSONTraversalStatusNodeAndDepthLimits(t *testing.T) {
	var nulls strings.Builder
	nulls.WriteByte('[')
	for i := 0; i < maxJSONNodes+1; i++ {
		if i > 0 {
			nulls.WriteByte(',')
		}
		nulls.WriteString("null")
	}
	nulls.WriteByte(']')
	var inputs []InputPoint
	status := flattenJSONInputsWithStatus("body.json", "", []byte(nulls.String()), &inputs)
	if !status.omitted || status.reason != jsonNodeLimitIncompleteReason {
		t.Fatalf("null flood status=%+v, want node limit", status)
	}

	deep := strings.Repeat(`[`, maxJSONDepth+2) + `"late"` + strings.Repeat(`]`, maxJSONDepth+2)
	inputs = nil
	status = flattenJSONInputsWithStatus("body.json", "", []byte(deep), &inputs)
	if !status.omitted || status.reason != jsonDepthLimitIncompleteReason {
		t.Fatalf("deep JSON status=%+v, want depth limit", status)
	}
}

func TestJSONExactInputDoesNotMarkIncomplete(t *testing.T) {
	body := []byte(`{"a":"one","b":"two"}`)
	req := httptest.NewRequest(http.MethodPost, "/json", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := &engine.RequestContext{Request: req, DecodedBody: body, Metadata: map[string]any{}}
	_ = extractCandidatesWithOptions(ctx, nil, 2)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); got {
		t.Fatalf("exact JSON input incorrectly marked incomplete: %#v", ctx.Metadata)
	}
}

func TestEscapedJSONFallbackSurfacesCollectorOverflow(t *testing.T) {
	var body strings.Builder
	body.WriteByte('{')
	for i := 0; i < maxCandidates+2; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"field_%03d":"ordinary\u0020value"`, i)
	}
	body.WriteString(`}`)
	raw := []byte(body.String())
	req := httptest.NewRequest(http.MethodPost, "/json", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	ctx := &engine.RequestContext{Request: req, DecodedBody: raw, Metadata: map[string]any{}}
	_ = extractCandidatesWithOptions(ctx, nil, 2)
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatalf("escaped JSON overflow not marked incomplete: %#v", ctx.Metadata)
	}
}

func TestEscapedLargeJSONKeepsLateAttackAfterNodeBudget(t *testing.T) {
	var body strings.Builder
	body.Grow(maxJSONTreeDecodeBytes + 1024)
	body.WriteByte('{')
	for i := 0; body.Len() <= maxJSONTreeDecodeBytes+128; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"field_%05d":"ordinary\u0020value"`, i)
	}
	body.WriteString(`,"cmd":"; whoami"}`)
	raw := []byte(body.String())
	var inputs []InputPoint
	status := flattenJSONInputsWithStatus("body.json", "", raw, &inputs)
	found := false
	for _, input := range inputs {
		if input.Name == "cmd" && input.Raw == "; whoami" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("late attack missing from streaming sample (status=%+v, inputs=%d)", status, len(inputs))
	}
}

func TestCandidateExactCapDuplicateRemainderComplete(t *testing.T) {
	var query strings.Builder
	for i := 0; i < 32; i++ {
		if i > 0 {
			query.WriteByte('&')
		}
		fmt.Fprintf(&query, "k%02d=v%02d", i, i)
	}
	query.WriteString("&k00=v00&k00=v00")
	req := httptest.NewRequest(http.MethodGet, "/?"+query.String(), nil)
	ctx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
	candidates := extractCandidatesWithOptions(ctx, nil, 2)
	if len(candidates) != maxCandidates {
		t.Fatalf("candidate count=%d, want exact cap %d", len(candidates), maxCandidates)
	}
	if got, _ := ctx.Metadata["semantic_input_incomplete"].(bool); got {
		t.Fatalf("duplicate-only remainder marked incomplete: %#v", ctx.Metadata)
	}
}

func TestJSONOverflowAddsRawCoverage(t *testing.T) {
	var body strings.Builder
	body.WriteByte('{')
	for i := 0; i < maxCandidates; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `"k%03d":"v%03d"`, i, i)
	}
	body.WriteString(`,"late":"value"}`)
	req := httptest.NewRequest(http.MethodPost, "/json", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", "application/json")
	inputs, status := bodyInputsWithTraversalStatus(req, []byte(body.String()))
	if !status.omitted {
		t.Fatalf("overflow JSON status missing: %+v", status)
	}
	foundRaw := false
	for _, input := range inputs {
		if input.Source == "body.raw" && input.Name == "body" {
			foundRaw = true
		}
	}
	if !foundRaw {
		t.Fatal("overflow JSON omitted body.raw coverage")
	}
}

func TestFormOverflowAddsRawCoverage(t *testing.T) {
	var body strings.Builder
	for i := 0; i < maxCandidates+1; i++ {
		if i > 0 {
			body.WriteByte('&')
		}
		fmt.Fprintf(&body, "k%03d=v%03d", i, i)
	}
	req := httptest.NewRequest(http.MethodPost, "/form", strings.NewReader(body.String()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inputs, status := bodyInputsWithTraversalStatus(req, []byte(body.String()))
	if !status.omitted || status.reason != bodyInputLimitReason {
		t.Fatalf("form overflow status=%+v, want body limit", status)
	}
	if len(inputs) == 0 || inputs[0].Source != "body.raw" {
		var first InputPoint
		if len(inputs) > 0 {
			first = inputs[0]
		}
		t.Fatalf("form overflow omitted body.raw coverage: first=%+v", first)
	}
}

func TestOversizedFormBodyFailsClosedBeforeParse(t *testing.T) {
	body := strings.Repeat("k=v&", maxInputRawBytes*maxCandidates/2)
	req := httptest.NewRequest(http.MethodPost, "/form", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inputs, status := bodyInputsWithTraversalStatus(req, []byte(body))
	if !status.omitted || status.reason != bodyInputLimitReason {
		t.Fatalf("oversized form status=%+v", status)
	}
	if len(inputs) != 1 || inputs[0].Source != "body.raw" {
		t.Fatalf("oversized form should retain bounded raw only: %+v", inputs)
	}
}

func TestMalformedFormBodySurfacesParseIncomplete(t *testing.T) {
	body := []byte("broken=%zz")
	req := httptest.NewRequest(http.MethodPost, "/form", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inputs, status := bodyInputsWithTraversalStatus(req, body)
	if !status.omitted || status.reason != formParseIncompleteReason {
		t.Fatalf("malformed form status=%+v", status)
	}
	if len(inputs) != 1 || inputs[0].Source != "body.raw" {
		t.Fatalf("malformed form should retain bounded raw: %+v", inputs)
	}
}

func TestLargeEscapedMalformedJSONKeepsEarlyAttackAndStatus(t *testing.T) {
	var body strings.Builder
	body.Grow(maxJSONTreeDecodeBytes + 32)
	body.WriteString(`{"cmd":"; whoami",`)
	for i := 0; body.Len() < maxJSONTreeDecodeBytes+16; i++ {
		fmt.Fprintf(&body, `"field_%05d":"ordinary\u0020value",`, i)
	}
	body.WriteString(`"tail":"unterminated"`)
	raw := []byte(body.String())
	req := httptest.NewRequest(http.MethodPost, "/json", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	inputs, status := bodyInputsWithTraversalStatus(req, raw)
	if !status.omitted || (status.reason != jsonParseIncompleteReason && status.reason != jsonCollectorLimitReason) {
		t.Fatalf("malformed escaped JSON status=%+v", status)
	}
	found := false
	for _, input := range inputs {
		if input.Name == "cmd" && input.Raw == "; whoami" {
			found = true
		}
	}
	if !found {
		t.Fatalf("early attack dropped from malformed JSON inputs: %+v", inputs[:minInt(len(inputs), 3)])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
