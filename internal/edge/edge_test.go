package edge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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
