package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type healthCheckRoundTripper func(*http.Request) (*http.Response, error)

func (f healthCheckRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type trackingHealthBody struct {
	*bytes.Reader
	read   int
	closed bool
}

func (b *trackingHealthBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackingHealthBody) Close() error {
	b.closed = true
	return nil
}

func TestHealthCheckerBoundsResponseDrain(t *testing.T) {
	body := &trackingHealthBody{Reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, 256<<10))}
	checker := NewHealthChecker(nil, NewHealthRegistry([]config.SiteConfig{{Upstreams: []config.UpstreamConfig{{Address: "http://health.test"}}}}))
	checker.client.Transport = healthCheckRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: make(http.Header)}, nil
	})
	site := config.SiteConfig{Upstreams: []config.UpstreamConfig{{Address: "http://health.test"}}}

	checker.check(site)

	if !body.closed {
		t.Fatal("health check did not close response body")
	}
	if body.read > (64<<10)+1 {
		t.Fatalf("health check drained unbounded response: read %d bytes", body.read)
	}
	if body.read == 0 {
		t.Fatal("health check did not inspect response body")
	}
}

func TestHealthCheckerDoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHits int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&redirectTargetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/metadata", http.StatusFound)
	}))
	defer upstream.Close()

	site := config.Default().Sites[0]
	site.Upstreams = []config.UpstreamConfig{{Address: upstream.URL}}
	site.WAF.HealthCheck.Enabled = true
	site.WAF.HealthCheck.Path = "/healthz"
	site.WAF.HealthCheck.Timeout = time.Second
	registry := NewHealthRegistry([]config.SiteConfig{site})
	checker := NewHealthChecker([]config.SiteConfig{site}, registry)

	checker.check(site)

	if got := atomic.LoadInt32(&redirectTargetHits); got != 0 {
		t.Fatalf("health check followed redirect target %d time(s)", got)
	}
	if !registry.Healthy(upstream.URL) {
		t.Fatalf("expected redirecting upstream to be treated as reachable without following redirect")
	}
}

func TestHealthRegistryUpdateSitesPreservesKnownStateAndDropsRemoved(t *testing.T) {
	first := config.SiteConfig{Upstreams: []config.UpstreamConfig{{Address: "http://127.0.0.1:8001"}}}
	registry := NewHealthRegistry([]config.SiteConfig{first})
	registry.Set(first.Upstreams[0].Address, false)
	second := config.SiteConfig{Upstreams: []config.UpstreamConfig{
		{Address: "http://127.0.0.1:8001"},
		{Address: "http://127.0.0.1:8002"},
	}}
	registry.UpdateSites([]config.SiteConfig{second})
	if registry.Healthy(first.Upstreams[0].Address) {
		t.Fatal("existing unhealthy state was reset during site update")
	}
	if !registry.Healthy(second.Upstreams[1].Address) {
		t.Fatal("new upstream must start healthy")
	}
	registry.UpdateSites([]config.SiteConfig{{Upstreams: []config.UpstreamConfig{{Address: second.Upstreams[1].Address}}}})
	registry.Set(first.Upstreams[0].Address, false)
	if _, exists := registry.Snapshot()[normalizeUpstream(first.Upstreams[0].Address)]; exists {
		t.Fatal("removed upstream was reinserted by a stale health check")
	}
}

func TestHealthCheckerUpdateSitesStopsOldGeneration(t *testing.T) {
	var firstHits atomic.Int32
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer firstServer.Close()
	var secondHits atomic.Int32
	secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer secondServer.Close()

	makeSite := func(address string) config.SiteConfig {
		site := config.Default().Sites[0]
		site.Upstreams = []config.UpstreamConfig{{Address: address}}
		site.WAF.HealthCheck.Enabled = true
		site.WAF.HealthCheck.Interval = 5 * time.Millisecond
		site.WAF.HealthCheck.Timeout = time.Second
		return site
	}
	first := makeSite(firstServer.URL)
	second := makeSite(secondServer.URL)
	registry := NewHealthRegistry([]config.SiteConfig{first})
	checker := NewHealthChecker([]config.SiteConfig{first}, registry)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.Start(ctx)
	waitForHealthHits(t, &firstHits)
	registry.UpdateSites([]config.SiteConfig{second})
	checker.UpdateSites([]config.SiteConfig{second})
	firstAfterUpdate := firstHits.Load()
	waitForHealthHits(t, &secondHits)
	time.Sleep(20 * time.Millisecond)
	if got := firstHits.Load(); got != firstAfterUpdate {
		t.Fatalf("old checker generation continued after update: before=%d after=%d", firstAfterUpdate, got)
	}
}

func waitForHealthHits(t *testing.T, hits *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("health checker did not reach upstream")
	}
}
