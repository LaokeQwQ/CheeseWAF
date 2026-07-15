package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAnalyzerPathAllowlistSkipsDetection(t *testing.T) {
	a := NewAnalyzer("block")
	a.SetAllowlists([]string{"/health", "/static/*"}, nil)

	req := httptest.NewRequest(http.MethodGet, "http://x/health?id=1'+OR+1=1--", nil)
	reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("path allowlist must skip SQLi on /health, got %#v", got)
	}
	if reqCtx.Metadata["semantic_skipped"] != "path_allowlist" {
		t.Fatalf("expected semantic_skipped metadata, got %#v", reqCtx.Metadata)
	}

	// Prefix rule
	req2 := httptest.NewRequest(http.MethodGet, "http://x/static/app.js?x=1'+OR+1=1--", nil)
	reqCtx2 := &engine.RequestContext{Request: req2, Metadata: map[string]any{}}
	got2, err := a.Detect(context.Background(), reqCtx2)
	if err != nil {
		t.Fatal(err)
	}
	if got2 != nil && got2.Detected {
		t.Fatalf("prefix path allowlist must skip, got %#v", got2)
	}
}

func TestAnalyzerParamAllowlistSkipsField(t *testing.T) {
	a := NewAnalyzer("block")
	a.SetAllowlists(nil, []string{"content", "body"})

	// Allowlisted param carries classic SQLi — must not block.
	req := httptest.NewRequest(http.MethodGet, "http://x/post?content=1'+OR+'1'='1&id=ok", nil)
	reqCtx := &engine.RequestContext{Request: req}
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("param allowlist content must not trigger, got %#v", got)
	}

	// Non-allowlisted param still detects.
	req2 := httptest.NewRequest(http.MethodGet, "http://x/post?q=1'+OR+'1'='1", nil)
	reqCtx2 := &engine.RequestContext{Request: req2}
	got2, err := a.Detect(context.Background(), reqCtx2)
	if err != nil {
		t.Fatal(err)
	}
	if got2 == nil || !got2.Detected || got2.Category != "sqli" {
		t.Fatalf("expected SQLi on non-allowlisted param, got %#v", got2)
	}
}

func TestPathAllowlistedRules(t *testing.T) {
	rules := []string{"/api/health", "/assets/*"}
	if !pathAllowlisted("/api/health", rules) {
		t.Fatal("exact match")
	}
	if !pathAllowlisted("/api/health/live", rules) {
		t.Fatal("directory prefix")
	}
	if !pathAllowlisted("/assets/a.css", rules) {
		t.Fatal("star prefix")
	}
	if pathAllowlisted("/api/users", rules) {
		t.Fatal("should not match unrelated path")
	}
}
