package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

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
