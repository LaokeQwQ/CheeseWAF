package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/adapterapi"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type adapterBlockDetector struct{}

func (adapterBlockDetector) ID() string    { return "adapter-test" }
func (adapterBlockDetector) Name() string  { return "adapter test detector" }
func (adapterBlockDetector) Priority() int { return 300 }
func (adapterBlockDetector) Detect(_ context.Context, request *engine.RequestContext) (*engine.DetectionResult, error) {
	if request == nil || request.Request == nil || !strings.Contains(request.Request.URL.Path, "blocked") {
		return nil, nil
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: "adapter-test",
		Category:   "sqli",
		Severity:   engine.SeverityCritical,
		Action:     engine.ActionBlock,
		Confidence: 1,
		Message:    "adapter test attack",
	}, nil
}

func TestInspectAdapterUsesSitePipeline(t *testing.T) {
	cfg := config.Default()
	cfg.Sites = []config.SiteConfig{{
		ID:      "site-1",
		Name:    "adapter test",
		Domains: []string{"app.example"},
		Enabled: true,
		WAF: config.WAFConfig{
			Enabled:       true,
			Mode:          "block",
			ParanoiaLevel: 3,
		},
	}}
	cfg.Protection.Policy.WebAttack = config.ProtectionLevelStrict
	server, err := NewServer(&cfg, engine.NewPipeline(adapterBlockDetector{}), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	base := adapterapi.Request{
		ContractVersion: adapterapi.Version,
		Source:          adapterapi.SourceGeneric,
		Method:          http.MethodGet,
		Scheme:          "https",
		Authority:       "app.example",
		Path:            "/safe",
		BodyState:       adapterapi.BodyStateAbsent,
		Client:          adapterapi.ClientContext{IP: "203.0.113.10"},
	}
	allow, err := server.InspectAdapter(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if allow.Action != adapterapi.ActionAllow {
		t.Fatalf("safe action = %q", allow.Action)
	}

	blocked := base
	blocked.Path = "/blocked"
	decision, err := server.InspectAdapter(context.Background(), blocked)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != adapterapi.ActionBlock || decision.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked decision = %+v", decision)
	}
}
