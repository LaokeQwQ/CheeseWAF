package edge

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/andybalholm/brotli"
)

func TestHeaderModifierSetAddDelete(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set("X-Origin-Secret", "leak")
	modifier := NewHeaderModifier(config.HeaderPolicyConfig{Enabled: true, Rules: []config.HeaderRuleConfig{
		{ID: "set", Operation: "set", Header: "X-CheeseWAF", Value: "edge", Enabled: true},
		{ID: "delete", Operation: "delete", Header: "X-Origin-Secret", Enabled: true},
	}})
	modifier.Apply(req)
	if got := req.Header.Get("X-CheeseWAF"); got != "edge" {
		t.Fatalf("header not set: %q", got)
	}
	if got := req.Header.Get("X-Origin-Secret"); got != "" {
		t.Fatalf("header not deleted: %q", got)
	}
}

func TestCacheStoresAndReturnsResponse(t *testing.T) {
	cache := NewCache(config.CachePolicyConfig{
		Enabled:      true,
		Mode:         "public",
		TTL:          time.Minute,
		StatusCodes:  []int{http.StatusOK},
		PathPrefixes: []string{"/assets/"},
		MaxBodyBytes: 1024,
	})
	req := httptest.NewRequest(http.MethodGet, "http://localhost/assets/app.js", nil)
	resp := CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/javascript"}}, Body: []byte("console.log(1)")}
	cache.Store(req, resp)
	cached, ok := cache.Get(req)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(cached.Body) != "console.log(1)" || cached.Header.Get("X-CheeseWAF-Cache") != "HIT" {
		t.Fatalf("unexpected cached response: %+v", cached)
	}
}

func TestCacheAccountingHandlesOverwriteExpiryAndOversize(t *testing.T) {
	cache := NewCache(config.CachePolicyConfig{Enabled: true, Mode: "private", TTL: time.Millisecond, MaxBodyBytes: 1 << 20}).WithMaxTotalBytes(1024)
	req := httptest.NewRequest(http.MethodGet, "https://example.test/data", nil)
	req.Header.Set("Authorization", "Bearer token")
	resp := CapturedResponse{Status: http.StatusOK, Header: make(http.Header), Body: []byte("payload")}
	cache.Store(req, resp)
	first := cache.CurrentBytes()
	cache.Store(req, resp)
	if got := cache.CurrentBytes(); got != first {
		t.Fatalf("overwrite double-counted bytes: first=%d after=%d", first, got)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := cache.Get(req); ok {
		t.Fatal("expired entry returned a hit")
	}
	if got := cache.CurrentBytes(); got != 0 {
		t.Fatalf("expired entry left %d accounted bytes", got)
	}

	oversize := NewCache(config.CachePolicyConfig{Enabled: true, Mode: "public", MaxBodyBytes: 1 << 20}).WithMaxTotalBytes(64)
	oversize.Store(httptest.NewRequest(http.MethodGet, "https://example.test/large", nil), resp)
	if oversize.KeyCount() != 0 || oversize.CurrentBytes() != 0 {
		t.Fatalf("single entry larger than budget was retained: keys=%d bytes=%d", oversize.KeyCount(), oversize.CurrentBytes())
	}
}

func TestCacheUsesLRUAndRejectsVary(t *testing.T) {
	cache := NewCache(config.CachePolicyConfig{Enabled: true, Mode: "public", TTL: time.Minute, MaxBodyBytes: 1 << 20}).WithMaxEntries(2)
	response := CapturedResponse{Status: http.StatusOK, Header: make(http.Header), Body: []byte("ok")}
	request := func(path string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "https://example.test"+path, nil)
	}
	cache.Store(request("/a"), response)
	cache.Store(request("/b"), response)
	if _, ok := cache.Get(request("/a")); !ok {
		t.Fatal("expected /a cache hit")
	}
	cache.Store(request("/c"), response)
	if _, ok := cache.Get(request("/b")); ok {
		t.Fatal("least recently used /b entry was not evicted")
	}

	vary := response
	vary.Header = http.Header{"Vary": []string{"X-Tenant"}}
	cache.Store(request("/vary"), vary)
	if _, ok := cache.Get(request("/vary")); ok {
		t.Fatal("response with Vary must not be cached")
	}
}

func TestCacheKeySeparatesIdentityAndRepresentationDimensions(t *testing.T) {
	first := httptest.NewRequest(http.MethodGet, "https://example.test/data", nil)
	first.Header.Set("Authorization", "a|b")
	first.Header.Set("Cookie", "c")
	second := httptest.NewRequest(http.MethodGet, "https://example.test/data", nil)
	second.Header.Set("Authorization", "a")
	second.Header.Set("Cookie", "b|c")
	if cacheKey(first) == cacheKey(second) {
		t.Fatal("length-delimiter identity collision produced the same cache key")
	}
	third := first.Clone(first.Context())
	third.Header = first.Header.Clone()
	third.Header.Set("Accept", "application/json")
	if cacheKey(first) == cacheKey(third) {
		t.Fatal("Accept representation dimension was omitted from cache key")
	}
}

func TestCompressorAppliesGzip(t *testing.T) {
	compressor := NewCompressor(config.CompressionPolicyConfig{
		Enabled:      true,
		Algorithms:   []string{"gzip"},
		Level:        1,
		MinBytes:     4,
		ContentTypes: []string{"text/"},
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	body := strings.Repeat("hello ", 128)
	resp := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: []byte(body)}
	compressor.Apply(req, resp)
	if resp.Header.Get("Content-Encoding") != "gzip" || len(resp.Body) >= len(body) {
		t.Fatalf("expected gzip compression, headers=%v len=%d", resp.Header, len(resp.Body))
	}
}

func TestCompressorPrefersBrotliAndFallsBackToGzip(t *testing.T) {
	compressor := NewCompressor(config.CompressionPolicyConfig{
		Enabled:      true,
		Algorithms:   []string{"br", "gzip"},
		Level:        5,
		MinBytes:     4,
		ContentTypes: []string{"text/"},
	})
	body := strings.Repeat("attack intel ", 128)
	resp := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: []byte(body)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	compressor.Apply(req, resp)
	if got := resp.Header.Get("Content-Encoding"); got != "br" {
		t.Fatalf("expected br compression, got %q", got)
	}
	decoded, err := io.ReadAll(brotli.NewReader(bytes.NewReader(resp.Body)))
	if err != nil {
		t.Fatalf("decode br: %v", err)
	}
	if string(decoded) != body {
		t.Fatalf("unexpected br payload")
	}

	resp = &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: []byte(body)}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	compressor.Apply(req, resp)
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("expected gzip fallback, got %q", got)
	}
}
