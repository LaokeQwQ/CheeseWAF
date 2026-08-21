package rules

import (
	"context"
	"net/http"
	"strings"
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

func TestEngineClipsLongBodyPayload(t *testing.T) {
	needle := "EVIL_NEEDLE_TOKEN"
	// 4KB body with needle near the middle so a window around the match is required.
	prefix := strings.Repeat("A", 2000)
	suffix := strings.Repeat("B", 2000)
	body := prefix + needle + suffix

	compiled, err := FromConfig([]config.CustomRuleConfig{{
		ID: "long-body", Name: "Long Body Needle", Pattern: needle, Location: "body", Action: "block", Severity: "high", Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := New(compiled).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected {
		t.Fatalf("expected detection, got %+v", result)
	}
	if len(result.Payload) > 512 {
		t.Fatalf("Payload length %d exceeds 512-byte clip limit", len(result.Payload))
	}
	if !strings.Contains(result.Payload, needle) {
		t.Fatalf("clipped Payload lost match needle: %q", result.Payload)
	}
}
