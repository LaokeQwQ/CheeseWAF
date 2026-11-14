package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/adapterinspect"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestAdminAdapterRespectsSiteProtection(t *testing.T) {
	for _, level := range []string{config.ProtectionLevelOff, config.ProtectionLevelStrict} {
		t.Run(level, func(t *testing.T) {
			cfg := config.Default()
			cfg.Sites = []config.SiteConfig{{ID: "site-1", Domains: []string{"app.example"}, Enabled: true, WAF: config.WAFConfig{Enabled: true, Mode: "block", ParanoiaLevel: 3}}}
			cfg.Protection.Policy.WebAttack = level
			server, err := NewServer(&cfg, engine.NewPipeline(adapterBlockDetector{}), noopSink{})
			if err != nil {
				t.Fatal(err)
			}
			handler := adapterinspect.New(adapterinspect.Options{
				ResolveSite: func(string) (string, int64, bool) { return "site-1", 8 << 20, true },
				Inspect:     server.InspectAdminAdapter,
			})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest("POST", "/api/v1/adapter/inspect", strings.NewReader(`{"contract_version":"v1","authority":"app.example","method":"GET","path":"/blocked"}`)))
			var result adapterinspect.Decision
			if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			want := "block"
			if level == config.ProtectionLevelOff {
				want = "log"
			}
			if result.Action != want {
				t.Fatalf("action=%s want=%s response=%s", result.Action, want, recorder.Body.String())
			}
		})
	}
}
