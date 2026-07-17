package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestSiteForHostDoesNotFallBackToFirstEnabledSite(t *testing.T) {
	t.Parallel()
	lb := NewLoadBalancer([]config.SiteConfig{
		{
			ID:      "tenant-a",
			Enabled: true,
			Domains: []string{"a.example.test"},
			Upstreams: []config.UpstreamConfig{
				{Address: "http://127.0.0.1:1", Weight: 1},
			},
		},
		{
			ID:      "tenant-b",
			Enabled: true,
			Domains: []string{"b.example.test"},
			Upstreams: []config.UpstreamConfig{
				{Address: "http://127.0.0.1:2", Weight: 1},
			},
		},
	})

	matched := lb.SiteForHost("a.example.test")
	if matched.ID != "tenant-a" {
		t.Fatalf("expected tenant-a, got %+v", matched)
	}
	matched = lb.SiteForHost("B.EXAMPLE.TEST:443")
	if matched.ID != "tenant-b" {
		t.Fatalf("expected tenant-b with port stripped, got %+v", matched)
	}

	unmatched := lb.SiteForHost("unknown.example.test")
	if unmatched.ID != "" || unmatched.Enabled {
		t.Fatalf("unmatched host must not fall back to another tenant, got %+v", unmatched)
	}
}

func TestServerRejectsUnmatchedHostWithMisdirectedRequest(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Domains = []string{"app.example.test"}
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Protection.Bot.Enabled = true
	cfg.Protection.Bot.JSChallenge = true
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}

	// Unmatched host must not inherit first tenant (and must not bot-challenge under it).
	badReq := httptest.NewRequest(http.MethodGet, "http://other.example.test/", nil)
	badReq.Host = "other.example.test"
	badReq.Header.Set("User-Agent", "sqlmap")
	badRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421 for unmatched host, got %d body=%q", badRec.Code, badRec.Body.String())
	}
	if upstreamHits != 0 {
		t.Fatalf("unmatched host reached upstream %d times", upstreamHits)
	}

	// Matched host still works.
	okReq := httptest.NewRequest(http.MethodGet, "http://app.example.test/", nil)
	okReq.Host = "app.example.test"
	okRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(okRec, okReq)
	if okRec.Code == http.StatusMisdirectedRequest {
		t.Fatalf("matched host must not get 421, got %d body=%q", okRec.Code, okRec.Body.String())
	}
}
