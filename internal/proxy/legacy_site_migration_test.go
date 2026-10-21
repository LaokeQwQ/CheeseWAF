package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestLegacyStoredSiteInheritsGlobalACLPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	advanced, err := storage.DecodeStoredSiteAdvanced([]byte(`{"origin":{"scheme":"http"},"protection":{"bot":false,"ratelimit":false,"acl":false,"apisec":false}}`))
	if err != nil {
		t.Fatal(err)
	}
	legacy := storage.SiteToConfig(storage.Site{
		ID: "legacy", Name: "legacy", Domains: []string{"legacy.example.test"},
		Upstreams: []string{upstream.URL}, Advanced: advanced,
		Enabled: true, WAFEnabled: true, WAFMode: "block",
	})
	for _, enabled := range []bool{false, true} {
		cfg := config.Default()
		cfg.Sites = []config.SiteConfig{legacy}
		cfg.Protection.IP.Whitelist, cfg.Protection.IP.Blacklist = nil, nil
		cfg.Protection.Bot.Enabled = false
		cfg.Protection.RateLimit.Enabled = false
		cfg.Protection.Policy.WebAttack = config.ProtectionLevelOff
		cfg.Protection.ACL = config.ACLProtectionConfig{Enabled: enabled, Rules: []config.ACLRuleConfig{{
			ID: "deny", PathPrefix: "/deny", Action: "block", Severity: "high", Enabled: true,
		}}}
		server, err := NewServer(&cfg, engine.NewPipeline(), &captureSink{})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://legacy.example.test/deny", nil))
		want := http.StatusNoContent
		if enabled {
			want = http.StatusForbidden
		}
		if recorder.Code != want {
			t.Fatalf("global ACL enabled=%v: status=%d, want %d", enabled, recorder.Code, want)
		}
	}
}
