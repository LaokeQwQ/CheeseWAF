package semantic

import (
	"context"
	"errors"
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
