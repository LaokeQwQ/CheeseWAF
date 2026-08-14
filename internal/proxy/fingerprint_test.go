package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
)

func TestClientFingerprintIsStable(t *testing.T) {
	first := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	first.Header.Set("User-Agent", "ReviewAgent/1.0")
	first.Header.Set("Accept-Language", "zh-CN")
	second := httptest.NewRequest(http.MethodGet, "http://localhost/other", nil)
	second.Header.Set("User-Agent", "ReviewAgent/1.0")
	second.Header.Set("Accept-Language", "zh-CN")
	got := clientFingerprint(first)
	if got == "" || got != clientFingerprint(second) {
		t.Fatalf("fingerprint must be stable, got %q vs %q", got, clientFingerprint(second))
	}
	if len(got) != 16 {
		t.Fatalf("fingerprint length: got %d want 16", len(got))
	}
	if clientFingerprint(httptest.NewRequest(http.MethodGet, "http://localhost/", nil)) != "" {
		t.Fatal("empty UA and language must not invent a fingerprint")
	}
}

func TestFingerprintDeniedBlocksMatchingClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	probe := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	probe.Header.Set("User-Agent", "ReviewAgent/1.0")
	probe.Header.Set("Accept-Language", "zh-CN")
	fp := clientFingerprint(probe)

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.SemanticPolicy.FingerprintDeny = []string{fp}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	server, err := NewServer(&cfg, engine.NewPipeline(semantic.NewAnalyzer("block", 3)), &captureSink{})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.Header.Set("User-Agent", "ReviewAgent/1.0")
	req.Header.Set("Accept-Language", "zh-CN")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied fingerprint must block, code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAllowlistSkipLogsQueryButNotBarePath(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: upstream.URL, Weight: 1}}
	cfg.Sites[0].WAF.SemanticPolicy.PathAllowlist = []string{"/health"}
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil

	analyzer := semantic.NewAnalyzer("block", 3)
	analyzer.SetAllowlists([]string{"/health"}, nil)
	sink := &captureSink{}
	server, err := NewServer(&cfg, engine.NewPipeline(analyzer), sink)
	if err != nil {
		t.Fatal(err)
	}

	bare := httptest.NewRequest(http.MethodGet, "http://localhost/health", nil)
	server.Handler().ServeHTTP(httptest.NewRecorder(), bare)
	if loggedAllowlist(sink) {
		t.Fatalf("bare /health must not write an allowlist log, got %#v", sink.entries)
	}

	query := httptest.NewRequest(http.MethodGet, "http://localhost/health?q="+url.QueryEscape("1"), nil)
	server.Handler().ServeHTTP(httptest.NewRecorder(), query)
	if !loggedAllowlist(sink) {
		t.Fatalf("allowlisted path with query must be visible in logs, got %#v", sink.entries)
	}
}

func loggedAllowlist(sink *captureSink) bool {
	for _, entry := range sink.entries {
		if entry != nil && entry.Message == "allowlist: path_allowlist" {
			return true
		}
	}
	return false
}
