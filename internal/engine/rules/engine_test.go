package rules

import (
	"context"
	"net/http"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestEngineMatchesCustomRule(t *testing.T) {
	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "admin", Name: "Admin Probe", Pattern: `(?i)/admin`, Location: "uri", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "/admin", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected custom rule block, got %+v", result)
	}
}
