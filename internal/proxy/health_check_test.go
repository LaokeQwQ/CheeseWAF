package proxy

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHealthCheckerUsesStatusAndConfiguredThresholds(t *testing.T) {
	site := config.Default().Sites[0]
	site.Upstreams = []config.UpstreamConfig{{Address: "http://health.test"}}
	site.WAF.HealthCheck.HealthyThreshold = 2
	site.WAF.HealthCheck.UnhealthyThreshold = 2
	registry := NewHealthRegistry([]config.SiteConfig{site})
	checker := NewHealthChecker([]config.SiteConfig{site}, registry)
	status := http.StatusInternalServerError
	checker.client.Transport = healthCheckRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: http.NoBody, Header: make(http.Header)}, nil
	})

	checker.check(site)
	if !registry.Healthy(site.Upstreams[0].Address) {
		t.Fatal("one failure must not cross unhealthy threshold")
	}
	checker.check(site)
	if registry.Healthy(site.Upstreams[0].Address) {
		t.Fatal("5xx must become unhealthy at configured threshold")
	}
	status = http.StatusNotFound
	checker.check(site)
	checker.check(site)
	if registry.Healthy(site.Upstreams[0].Address) {
		t.Fatal("4xx must remain an unhealthy observation")
	}
	status = http.StatusFound
	checker.check(site)
	if registry.Healthy(site.Upstreams[0].Address) {
		t.Fatal("one success must not cross healthy threshold")
	}
	checker.check(site)
	if !registry.Healthy(site.Upstreams[0].Address) {
		t.Fatal("3xx must become healthy at configured threshold")
	}
}

func TestHealthCheckerUsesWebSocketUpgradeForWSUpstreams(t *testing.T) {
	var upgradeSeen atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Connection") != "Upgrade" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upgradeSeen.Store(true)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support hijacking")
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("hijack WebSocket health connection: %v", err)
		}
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		_ = conn.Close()
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	site := config.Default().Sites[0]
	site.Upstreams = []config.UpstreamConfig{{Address: wsURL}}
	site.WAF.HealthCheck.HealthyThreshold = 1
	registry := NewHealthRegistry([]config.SiteConfig{site})
	checker := NewHealthChecker([]config.SiteConfig{site}, registry)
	checker.check(site)
	if !upgradeSeen.Load() {
		t.Fatal("health check did not send a WebSocket upgrade")
	}
	if !registry.Healthy(wsURL) {
		t.Fatal("successful WebSocket handshake must keep upstream healthy")
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
	// Probe starts are measured inside the checker. Observing them at the HTTP
	// handler measures transport delivery instead: a request the retired
	// generation sent before cancellation can reach the handler afterwards, so
	// the handler cannot distinguish "new probe" from "late delivery".
	var firstProbes atomic.Int32
	var secondProbes atomic.Int32
	makeSite := func(address string) config.SiteConfig {
		site := config.Default().Sites[0]
		site.Upstreams = []config.UpstreamConfig{{Address: address}}
		site.WAF.HealthCheck.Enabled = true
		site.WAF.HealthCheck.Interval = 5 * time.Millisecond
		site.WAF.HealthCheck.Timeout = time.Second
		return site
	}
	first := makeSite("first.example")
	second := makeSite("second.example")
	registry := NewHealthRegistry([]config.SiteConfig{first})
	checker := NewHealthChecker([]config.SiteConfig{first}, registry)
	checker.probe = func(_ context.Context, site config.SiteConfig) {
		if site.Upstreams[0].Address == "first.example" {
			firstProbes.Add(1)
			return
		}
		secondProbes.Add(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checker.Start(ctx)
	waitForProbes(t, &firstProbes)

	checker.UpdateSites([]config.SiteConfig{second})
	afterUpdate := firstProbes.Load()
	waitForProbes(t, &secondProbes)
	// UpdateSites waits for the retired generation's loops to exit, so no probe
	// for the old upstream may start after it returns.
	time.Sleep(20 * time.Millisecond)
	if got := firstProbes.Load(); got != afterUpdate {
		t.Fatalf("old checker generation started %d probes after the update", got-afterUpdate)
	}
}

func waitForProbes(t *testing.T, probes *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for probes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if probes.Load() == 0 {
		t.Fatal("health checker did not run a probe")
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
