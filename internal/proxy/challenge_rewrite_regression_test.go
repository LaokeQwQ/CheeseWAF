package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func newChallengeRewriteTestServer(t *testing.T, configure func(*config.Config)) (*Server, *atomic.Int64) {
	t.Helper()
	calls := new(atomic.Int64)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Upstream-URI", r.URL.RequestURI())
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cfg := reviewProxyConfig(upstream.URL)
	cfg.Protection.Bot.Secret = strings.Repeat("s", 48)
	cfg.Protection.Bot.Enabled = false
	cfg.APISec.Enabled = false
	cfg.Sites[0].WAF.Enabled = false
	cfg.Sites[0].WAF.Rewrite = []config.RewriteRuleConfig{{ID: "all", Enabled: true, Pattern: "^/.*$", Replacement: "/rewritten"}}
	if configure != nil {
		configure(&cfg)
	}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server, calls
}

func TestChallengeVerifyRemainsReservedUnderSiteRewrite(t *testing.T) {
	for _, redirectCode := range []int{0, http.StatusTemporaryRedirect} {
		name := "rewrite"
		if redirectCode != 0 {
			name = "redirect"
		}
		t.Run(name, func(t *testing.T) {
			server, calls := newChallengeRewriteTestServer(t, func(cfg *config.Config) {
				cfg.Sites[0].WAF.Rewrite[0].RedirectCode = redirectCode
			})
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				req := httptest.NewRequest(method, "http://localhost"+botBehaviorVerifyPath, strings.NewReader(`{"token":"unknown"}`))
				rec := httptest.NewRecorder()
				server.Handler().ServeHTTP(rec, req)
				want := http.StatusUnauthorized
				if method == http.MethodGet {
					want = http.StatusMethodNotAllowed
				}
				if rec.Code != want || rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("%s verify was not handled internally: status=%d body=%q", method, rec.Code, rec.Body.String())
				}
				if method == http.MethodGet && rec.Header().Get("Allow") != http.MethodPost {
					t.Fatal("verify method contract changed")
				}
				if calls.Load() != 0 {
					t.Fatalf("verify reached upstream %d times", calls.Load())
				}
			}
		})
	}
}

func TestChallengeVerifyRewriteKeepsBodyLimit(t *testing.T) {
	server, calls := newChallengeRewriteTestServer(t, nil)
	for _, chunked := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodPost, "http://localhost"+botBehaviorVerifyPath, strings.NewReader(`{"token":"`+strings.Repeat("x", 64<<10)+`"}`))
		if chunked {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || calls.Load() != 0 {
			t.Fatalf("chunked=%v verify body limit bypassed: status=%d upstream=%d", chunked, rec.Code, calls.Load())
		}
	}
}

func TestChallengeVerifyRewriteKeepsIPAndGeoGates(t *testing.T) {
	for _, gate := range []string{"ip", "geo"} {
		t.Run(gate, func(t *testing.T) {
			server, calls := newChallengeRewriteTestServer(t, func(cfg *config.Config) {
				if gate == "ip" {
					cfg.Protection.IP.Blacklist = []string{"203.0.113.10"}
				} else {
					cfg.Protection.IP.GeoIP = config.GeoIPConfig{Enabled: true, BlockedCountries: []string{"ZZ"}, CountryCIDRs: map[string][]string{"ZZ": {"203.0.113.0/24"}}}
				}
			})
			req := httptest.NewRequest(http.MethodPost, "http://localhost"+botBehaviorVerifyPath, strings.NewReader(`{"token":"unknown"}`))
			req.RemoteAddr = "203.0.113.10:1234"
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || calls.Load() != 0 {
				t.Fatalf("%s gate lost precedence: status=%d upstream=%d", gate, rec.Code, calls.Load())
			}
		})
	}
}

func TestChallengeReservationDoesNotDisableBusinessRewrite(t *testing.T) {
	server, calls := newChallengeRewriteTestServer(t, nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/ordinary", nil))
	if rec.Code != http.StatusNoContent || rec.Header().Get("X-Upstream-URI") != "/rewritten" || calls.Load() != 1 {
		t.Fatalf("ordinary rewrite changed: status=%d uri=%q upstream=%d", rec.Code, rec.Header().Get("X-Upstream-URI"), calls.Load())
	}
}
