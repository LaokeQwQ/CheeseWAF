package semantic

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestJSONDuplicateKeyFirstPayloadIsScanned(t *testing.T) {
	body := `{"q":"1' OR '1'='1","q":"benign"}`
	req := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "site-test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected {
		t.Fatalf("first duplicate-key payload was not inspected: result=%+v metadata=%+v", result, reqCtx.Metadata)
	}
	if got, _ := reqCtx.Metadata["semantic_input_incomplete"].(bool); !got {
		t.Fatal("duplicate JSON key must mark semantic input incomplete")
	}
}
