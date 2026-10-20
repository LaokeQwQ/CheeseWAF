package semantic

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestJSONDuplicateKeyCandidatesAndIncompleteSignal(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantDetection bool
	}{
		{
			name:          "first value is attack",
			body:          `{"q":"1' OR '1'='1","q":"benign"}`,
			wantDetection: true,
		},
		{
			name:          "last value is attack with escaped duplicate key",
			body:          `{"q":"benign","\u0071":"1' OR '1'='1"}`,
			wantDetection: true,
		},
		{
			name: "escaped duplicate benign key is still incomplete",
			body: `{"q":"ordinary text","\u0071":"another ordinary value"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			reqCtx, err := engine.NewRequestContext(req, "site-test")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
			if tc.wantDetection {
				if err != nil {
					t.Fatal(err)
				}
				if result == nil || !result.Detected {
					t.Fatalf("duplicate-key attack value was not inspected: result=%+v metadata=%+v", result, reqCtx.Metadata)
				}
			} else {
				if result != nil && result.Detected {
					t.Fatalf("benign duplicate values were detected: %+v", result)
				}
				if !errors.Is(err, ErrSemanticInputIncomplete) {
					t.Fatalf("benign duplicate keys must return an incomplete signal, got %v", err)
				}
			}
			if got, _ := reqCtx.Metadata["semantic_input_incomplete"].(bool); !got {
				t.Fatal("duplicate JSON key must mark semantic input incomplete")
			}
		})
	}
}

func TestJSONDuplicateKeysUnderGenericMediaType(t *testing.T) {
	body := []byte(`{"q":"1' OR '1'='1","q":"benign"}`)
	req := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "text/plain")
	inputs, status := bodyInputsWithTraversalStatus(req, body)
	if !status.omitted || status.reason != jsonDuplicateKeyReason {
		t.Fatalf("duplicate keys under generic media type status=%+v, want duplicate-key incomplete", status)
	}
	foundRaw := false
	for _, input := range inputs {
		if input.Source == "body.json.raw" && input.Name == "body" && input.Raw == string(body) {
			foundRaw = true
			break
		}
	}
	if !foundRaw {
		t.Fatalf("generic JSON duplicate-key raw candidate missing: %+v", inputs)
	}

	ctx, err := engine.NewRequestContext(req, "site-test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", 2).Detect(context.Background(), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected {
		t.Fatalf("attack in first duplicate value was not inspected: result=%+v metadata=%+v", result, ctx.Metadata)
	}
}

func TestJSONDuplicateScanBudgetCannotBecomeCompleteAfterMapCollapse(t *testing.T) {
	var keys strings.Builder
	for i := 0; i <= maxJSONNodes; i++ {
		if i > 0 {
			keys.WriteByte(',')
		}
		fmt.Fprintf(&keys, `{"k%d":null}`, i)
	}
	for _, budget := range []struct{ name, value string }{
		{"depth", strings.Repeat("[", maxJSONDepth+2) + `null` + strings.Repeat("]", maxJSONDepth+2)},
		{"keys", "[" + keys.String() + "]"},
		{"tokens", "[" + strings.Repeat("null,", maxJSONNodes*4) + "null]"},
	} {
		for _, malicious := range []bool{false, true} {
			for _, contentType := range []string{"application/json", "application/merge-patch+json", "text/plain"} {
				t.Run(fmt.Sprintf("%s/attack=%t/%s", budget.name, malicious, contentType), func(t *testing.T) {
					body := `{"\u0061":` + budget.value + `,"a":"safe",`
					if malicious {
						body += `"user":{"$ne":null},`
					}
					body += `"user":"alice"}`
					req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
					req.Header.Set("Content-Type", contentType)
					inputs, status := bodyInputsWithTraversalStatus(req, []byte(body))
					if !status.omitted || status.reason != jsonDuplicateScanLimitReason {
						t.Errorf("duplicate scan budget became a complete pass after map collapse: status=%+v inputs=%+v", status, inputs)
					}
					foundRaw := false
					for _, input := range inputs {
						if input.Source == "body.json.raw" && input.Raw == body {
							foundRaw = true
						}
					}
					if !foundRaw {
						t.Error("duplicate scan budget did not preserve structured raw JSON coverage")
					}
					ctx := &engine.RequestContext{Request: req, DecodedBody: []byte(body)}
					result, err := NewNoSQLiDetector("block").Detect(context.Background(), ctx)
					if malicious {
						if err != nil || result == nil || !result.Detected {
							t.Fatalf("raw JSON coverage lost overwritten attack: result=%+v err=%v metadata=%+v", result, err, ctx.Metadata)
						}
					} else if (result != nil && result.Detected) || !errors.Is(err, ErrSemanticInputIncomplete) {
						t.Fatalf("benign budget exhaustion must remain incomplete: result=%+v err=%v metadata=%+v", result, err, ctx.Metadata)
					}
					if ctx.Metadata["semantic_input_incomplete"] != true || ctx.Metadata["semantic_input_incomplete_reason"] != jsonDuplicateScanLimitReason {
						t.Fatalf("duplicate scan reason did not reach analyzer metadata: %+v", ctx.Metadata)
					}
				})
			}
		}
	}
}
