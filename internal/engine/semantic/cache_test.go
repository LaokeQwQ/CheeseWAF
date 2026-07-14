package semantic

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestCandidateCacheHitAndTTL(t *testing.T) {
	processCandidateCache.resetForTest()
	ProcessMetrics().ResetForTest()
	c := newCandidateCache(8, 50*time.Millisecond)
	key := candidateCacheKey("block", enabledCategoryFingerprint(map[string]bool{"sqli": true}), "1 union select 1")
	if _, ok := c.get(key); ok {
		t.Fatal("expected miss")
	}
	c.put(key, []Hit{{Category: "sqli", Payload: "1 union select 1", Confidence: 0.9}})
	got, ok := c.get(key)
	if !ok || len(got) != 1 || got[0].Category != "sqli" {
		t.Fatalf("expected cache hit, got ok=%v hits=%+v", ok, got)
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := c.get(key); ok {
		t.Fatal("expected TTL expiry miss")
	}
}

func TestAnalyzerCandidateCacheSpeedsRepeatedFields(t *testing.T) {
	processCandidateCache.resetForTest()
	ProcessMetrics().ResetForTest()
	a := NewAnalyzer("block", "sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti")
	req, _ := http.NewRequest(http.MethodGet, "/search?q=selecting+a+theme+for+dashboard", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Warm cache with clean traffic.
	for i := 0; i < 3; i++ {
		reqCtx.Metadata = map[string]any{}
		if _, err := a.Detect(context.Background(), reqCtx); err != nil {
			t.Fatal(err)
		}
	}
	snap := ProcessMetrics().Snapshot()
	if snap.CacheHits == 0 {
		t.Fatalf("expected cache hits after repeated clean requests, got hits=%d misses=%d", snap.CacheHits, snap.CacheMisses)
	}
	// Attack payload should still detect (and cache hit on repeat).
	req2, _ := http.NewRequest(http.MethodGet, "/search?q=1%20union%20select%20password%20from%20users", nil)
	ctx2, err := engine.NewRequestContext(req2, "default")
	if err != nil {
		t.Fatal(err)
	}
	res1, err := a.Detect(context.Background(), ctx2)
	if err != nil || res1 == nil || !res1.Detected || res1.Category != "sqli" {
		t.Fatalf("expected sqli detection, got %+v err=%v", res1, err)
	}
	ctx2.Metadata = map[string]any{}
	res2, err := a.Detect(context.Background(), ctx2)
	if err != nil || res2 == nil || !res2.Detected {
		t.Fatalf("expected cached sqli detection, got %+v err=%v", res2, err)
	}
}
