package edge

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

func TestCacheRejectsWebSocketUpgradeRequests(t *testing.T) {
	cache := NewCache(config.CachePolicyConfig{Enabled: true, Mode: "public", PathPrefixes: []string{"/"}})
	request := httptest.NewRequest(http.MethodGet, "http://example.test/socket", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	if cache.CaptureCandidate(request) {
		t.Fatal("WebSocket upgrade must not be a cache candidate")
	}
}

func TestCacheRejectsSensitiveMetadataAcrossRepeatedHeaders(t *testing.T) {
	cache := NewCache(config.CachePolicyConfig{Enabled: true, Mode: "public", PathPrefixes: []string{"/"}})
	request := httptest.NewRequest(http.MethodGet, "https://example.test/repeated", nil)

	cases := []struct {
		name   string
		header http.Header
	}{
		{name: "set-cookie", header: http.Header{"Set-Cookie": []string{"", "session=secret"}}},
		{name: "vary", header: http.Header{"Vary": []string{"Accept-Encoding", "Cookie"}}},
		{name: "cache-control", header: http.Header{"Cache-Control": []string{"public, max-age=60", "no-store"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache.Store(request, CapturedResponse{Status: http.StatusOK, Header: tc.header, Body: []byte("body")})
			if _, ok := cache.Get(request); ok {
				t.Fatalf("response with repeated %s metadata must not be cached", tc.name)
			}
		})
	}
	for _, header := range []string{"Cookie", "Authorization"} {
		t.Run("repeated-"+header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.test/repeated-identity", nil)
			request.Header[header] = []string{"", "secret"}
			if cache.CaptureCandidate(request) {
				t.Fatalf("public cache accepted repeated %s with a non-empty value", header)
			}
		})
	}
}

func TestCacheHonorsRevalidationAndRangeSemantics(t *testing.T) {
	cache := NewCache(config.CachePolicyConfig{Enabled: true, Mode: "public", PathPrefixes: []string{"/"}})
	response := CapturedResponse{Status: http.StatusOK, Header: make(http.Header), Body: []byte("body")}

	for _, directive := range []string{"no-cache", "max-age=0"} {
		t.Run("request-"+directive, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.test/revalidate", nil)
			request.Header.Set("Cache-Control", directive)
			cache.Store(request, response)
			if cache.CaptureCandidate(request) {
				t.Fatalf("request %q must bypass cache", directive)
			}
		})
	}

	noCacheResponse := response
	noCacheResponse.Header = http.Header{"Cache-Control": []string{"no-cache"}}
	noCacheRequest := httptest.NewRequest(http.MethodGet, "https://example.test/no-cache", nil)
	cache.Store(noCacheRequest, noCacheResponse)
	if _, ok := cache.Get(noCacheRequest); ok {
		t.Fatal("response with no-cache must not be stored")
	}

	for _, header := range []string{"Range", "If-Range"} {
		t.Run("request-"+header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.test/range", nil)
			request.Header.Set(header, "bytes=0-3")
			if cache.CaptureCandidate(request) {
				t.Fatalf("request with %s must bypass cache", header)
			}
		})
	}
	for _, header := range []string{"Range", "If-Range"} {
		t.Run("repeated-request-"+header, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://example.test/repeated-range", nil)
			request.Header[header] = []string{"", "bytes=0-3"}
			if cache.CaptureCandidate(request) {
				t.Fatalf("request with repeated %s must bypass cache", header)
			}
		})
	}

	partialRequest := httptest.NewRequest(http.MethodGet, "https://example.test/partial", nil)
	cache.Store(partialRequest, CapturedResponse{Status: http.StatusPartialContent, Header: http.Header{"Content-Range": []string{"bytes 0-3/10"}}, Body: []byte("part")})
	if _, ok := cache.Get(partialRequest); ok {
		t.Fatal("206/content-range response must not be stored")
	}
	repeatedRangeRequest := httptest.NewRequest(http.MethodGet, "https://example.test/repeated-content-range", nil)
	cache.Store(repeatedRangeRequest, CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Range": []string{"", "bytes 0-3/10"}}, Body: []byte("part")})
	if _, ok := cache.Get(repeatedRangeRequest); ok {
		t.Fatal("response with repeated Content-Range must not be stored")
	}
}

func TestCacheKeySeparatesSchemes(t *testing.T) {
	httpRequest := httptest.NewRequest(http.MethodGet, "http://example.test/data", nil)
	httpsRequest := httptest.NewRequest(http.MethodGet, "https://example.test/data", nil)
	if cacheKey(httpRequest) == cacheKey(httpsRequest) {
		t.Fatal("HTTP and HTTPS requests must have distinct cache keys")
	}
}

func TestCacheKeySeparatesOriginalAndRewrittenTargets(t *testing.T) {
	original := httptest.NewRequest(http.MethodGet, "https://example.test/public/path?x=1", nil)
	rewritten := original.Clone(original.Context())
	rewritten.URL.Path = "/internal/path"
	rewritten.RequestURI = "/public/path?x=1"
	if cacheKey(original) == cacheKey(rewritten) {
		t.Fatal("original and rewritten request targets must have distinct cache keys")
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

func TestCompressorPreservesRepeatedVaryAndSkipsNoTransformAndPartialResponses(t *testing.T) {
	compressor := NewCompressor(config.CompressionPolicyConfig{Enabled: true, Algorithms: []string{"gzip"}, MinBytes: 4, ContentTypes: []string{"text/"}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	body := strings.Repeat("compressible ", 128)

	noTransform := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}, "Vary": []string{"Origin", "Accept-Language"}, "Cache-Control": []string{"public", "no-transform"}}, Body: []byte(body)}
	compressor.Apply(req, noTransform)
	if noTransform.Header.Get("Content-Encoding") != "" || string(noTransform.Body) != body {
		t.Fatal("no-transform response was changed")
	}

	partial := &CapturedResponse{Status: http.StatusPartialContent, Header: http.Header{"Content-Type": []string{"text/plain"}, "Content-Range": []string{"bytes 0-99/1000"}}, Body: []byte(body)}
	compressor.Apply(req, partial)
	if partial.Header.Get("Content-Encoding") != "" || string(partial.Body) != body {
		t.Fatal("partial response was changed")
	}
	repeatedPartial := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}, "Content-Range": []string{"", "bytes 0-99/1000"}}, Body: []byte(body)}
	compressor.Apply(req, repeatedPartial)
	if repeatedPartial.Header.Get("Content-Encoding") != "" || string(repeatedPartial.Body) != body {
		t.Fatal("response with repeated Content-Range was changed")
	}

	authenticatedHTML := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: []byte(body)}
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	authenticatedRequest.Header["Cookie"] = []string{"", "session=secret"}
	authenticatedRequest.Header.Set("Accept-Encoding", "gzip")
	compressor.Apply(authenticatedRequest, authenticatedHTML)
	if authenticatedHTML.Header.Get("Content-Encoding") != "" {
		t.Fatal("authenticated HTML with repeated Cookie was compressed")
	}

	full := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}, "Vary": []string{"Origin", "Accept-Language"}}, Body: []byte(body)}
	compressor.Apply(req, full)
	if full.Header.Values("Vary")[0] != "Origin" || full.Header.Values("Vary")[1] != "Accept-Language" {
		t.Fatalf("existing repeated Vary values were not preserved: %#v", full.Header.Values("Vary"))
	}
	if !strings.Contains(strings.Join(full.Header.Values("Vary"), ","), "Accept-Encoding") {
		t.Fatalf("Accept-Encoding was not added to Vary: %#v", full.Header.Values("Vary"))
	}
	decoded, err := io.ReadAll(mustGzipReader(t, full.Body))
	if err != nil || string(decoded) != body {
		t.Fatalf("gzip payload integrity failure: err=%v", err)
	}

	qZero := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: []byte(body)}
	qRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	qRequest.Header.Set("Accept-Encoding", "gzip;q=0")
	compressor.Apply(qRequest, qZero)
	if qZero.Header.Get("Content-Encoding") != "" {
		t.Fatal("explicitly rejected gzip encoding was used")
	}
}

func mustGzipReader(t *testing.T, body []byte) io.ReadCloser {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("open gzip response: %v", err)
	}
	return reader
}

func BenchmarkCacheKeyMaphash(b *testing.B) {
	request := httptest.NewRequest(http.MethodGet, "https://example.test/assets/app.js?version=1", nil)
	request.Header.Set("Accept-Encoding", "gzip, br")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cacheKey(request)
	}
}

func BenchmarkCacheKeySHA256(b *testing.B) {
	request := httptest.NewRequest(http.MethodGet, "https://example.test/assets/app.js?version=1", nil)
	request.Header.Set("Accept-Encoding", "gzip, br")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		digest := sha256.New()
		writeCacheKeyPartSHA256(digest, request.Method)
		writeCacheKeyPartSHA256(digest, request.Host)
		writeCacheKeyPartSHA256(digest, request.URL.RequestURI())
		for _, name := range []string{"Authorization", "Cookie", "Origin", "Accept", "Accept-Language", "Accept-Encoding"} {
			writeCacheKeyPartSHA256(digest, name)
			values := request.Header.Values(name)
			writeCacheKeyLengthSHA256(digest, uint64(len(values)))
			for _, value := range values {
				writeCacheKeyPartSHA256(digest, value)
			}
		}
		_ = hex.EncodeToString(digest.Sum(nil))
	}
}

func writeCacheKeyPartSHA256(digest io.Writer, value string) {
	writeCacheKeyLengthSHA256(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeCacheKeyLengthSHA256(digest io.Writer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = digest.Write(encoded[:])
}

func BenchmarkCompressorGzipPooled(b *testing.B) {
	compressor := NewCompressor(config.CompressionPolicyConfig{Enabled: true, Algorithms: []string{"gzip"}, Level: 1, MinBytes: 4, ContentTypes: []string{"text/"}})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	body := []byte(strings.Repeat("compressible response body ", 128))
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		response := &CapturedResponse{Status: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: body}
		compressor.Apply(request, response)
	}
}

func BenchmarkCompressorGzipFreshWriter(b *testing.B) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	body := []byte(strings.Repeat("compressible response body ", 128))
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var buffer bytes.Buffer
		writer, _ := gzip.NewWriterLevel(&buffer, 1)
		_, _ = writer.Write(body)
		_ = writer.Close()
		if acceptsEncoding(request.Header.Get("Accept-Encoding"), "gzip") {
			_ = append([]byte(nil), buffer.Bytes()...)
		}
	}
}
