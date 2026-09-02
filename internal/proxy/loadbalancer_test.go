package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestWeightedLoadBalancerDoesNotExpandCandidates(t *testing.T) {
	site := config.SiteConfig{
		ID:          "weighted",
		LoadBalance: "weighted",
		Upstreams: []config.UpstreamConfig{
			{Address: "http://127.0.0.1:8001", Weight: 3},
			{Address: "http://127.0.0.1:8002", Weight: 1},
		},
	}
	lb := NewLoadBalancer([]config.SiteConfig{site})
	if got := len(lb.healthyUpstreams(site)); got != 2 {
		t.Fatalf("weighted candidates expanded to %d entries", got)
	}
	counts := map[string]int{}
	for range 8 {
		target, err := lb.Next(site, "")
		if err != nil {
			t.Fatal(err)
		}
		counts[target.Host]++
	}
	if counts["127.0.0.1:8001"] != 6 || counts["127.0.0.1:8002"] != 2 {
		t.Fatalf("weighted distribution = %#v, want 6:2", counts)
	}
}

func TestWeightedLoadBalancerLargeWeightKeepsBoundedCandidates(t *testing.T) {
	site := config.SiteConfig{ID: "large", LoadBalance: "weighted", Upstreams: []config.UpstreamConfig{
		{Address: "http://127.0.0.1:8001", Weight: 1_000_000_000},
		{Address: "http://127.0.0.1:8002", Weight: 1},
	}}
	lb := NewLoadBalancer([]config.SiteConfig{site})
	if got := len(lb.healthyUpstreams(site)); got != len(site.Upstreams) {
		t.Fatalf("large weights allocated %d candidates", got)
	}
	if _, err := lb.Next(site, ""); err != nil {
		t.Fatal(err)
	}
}

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

func TestIPHashIsNotRuneSum(t *testing.T) {
	upstreams := []config.UpstreamConfig{
		{Address: "http://127.0.0.1:8001", Weight: 1},
		{Address: "http://127.0.0.1:8002", Weight: 1},
		{Address: "http://127.0.0.1:8003", Weight: 1},
	}
	site := config.SiteConfig{ID: "hash", LoadBalance: "ip_hash", Upstreams: upstreams}
	differed := 0
	for a := 1; a <= 32; a++ {
		ip := fmt.Sprintf("10.0.%d.%d", a/16, a)
		runeIndex := 0
		for _, r := range ip {
			runeIndex += int(r)
		}
		runeIndex %= len(upstreams)
		if ipHashIndex(ip, upstreams) != runeIndex {
			differed++
		}
	}
	if differed == 0 {
		t.Fatal("ip_hash still matches rune-sum modulo N")
	}
	lb := NewLoadBalancer([]config.SiteConfig{site})
	first, err := lb.Next(site, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	again, err := lb.Next(site, "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if first.Host != again.Host {
		t.Fatalf("same client IP must stick, got %s then %s", first.Host, again.Host)
	}
}

func TestLeastConnPrefersIdleUpstream(t *testing.T) {
	site := config.SiteConfig{
		ID:          "least",
		LoadBalance: "least_conn",
		Upstreams: []config.UpstreamConfig{
			{Address: "http://127.0.0.1:8001", Weight: 1},
			{Address: "http://127.0.0.1:8002", Weight: 1},
		},
	}
	lb := NewLoadBalancer([]config.SiteConfig{site})
	busy, err := url.Parse("http://127.0.0.1:8001")
	if err != nil {
		t.Fatal(err)
	}
	release := lb.Track(busy)
	defer release()
	got, err := lb.Next(site, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "127.0.0.1:8002" {
		t.Fatalf("least_conn picked %s, want idle 8002", got.Host)
	}
}

func TestLoadBalancerMatchesIPv6LiteralHosts(t *testing.T) {
	site := config.SiteConfig{ID: "ipv6", Enabled: true, Domains: []string{"::1"}}
	lb := NewLoadBalancer([]config.SiteConfig{site})
	for _, host := range []string{"[::1]:8080", "[::1]", "::1"} {
		if got := lb.SiteForHost(host); got.ID != site.ID {
			t.Fatalf("SiteForHost(%q)=%q, want %q", host, got.ID, site.ID)
		}
	}
}
