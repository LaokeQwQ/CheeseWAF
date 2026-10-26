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

func TestInspectAdapterDistinguishesDisabledFromUnknownSite(t *testing.T) {
	cfg := config.Default()
	cfg.Sites = []config.SiteConfig{{
		ID:      "disabled-site",
		Name:    "disabled",
		Domains: []string{"disabled.example"},
		Enabled: false,
		WAF:     config.WAFConfig{Enabled: true, Mode: "block"},
	}}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	request := adapterapi.Request{
		ContractVersion: adapterapi.Version,
		Source:          adapterapi.SourceGeneric,
		Method:          http.MethodGet,
		Path:            "/",
		Authority:       "disabled.example",
		BodyState:       adapterapi.BodyStateAbsent,
	}
	decision, err := server.InspectAdapter(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != adapterapi.ActionAllow {
		t.Fatalf("disabled site action = %q, want allow", decision.Action)
	}
	request.Authority = "unknown.example"
	decision, err = server.InspectAdapter(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != adapterapi.ActionBlock {
		t.Fatalf("unknown site action = %q, want block", decision.Action)
	}
}

// A site that configured an open/observe budget policy must keep it on the
// adapter path: the pipeline defaults a missing value to closed, which would
// challenge requests the site chose to let through.
type adapterPolicyProbe struct {
	seen chan string
}

func (p adapterPolicyProbe) ID() string    { return "adapter-policy-probe" }
func (p adapterPolicyProbe) Name() string  { return "adapter policy probe" }
func (p adapterPolicyProbe) Priority() int { return 300 }
func (p adapterPolicyProbe) Detect(_ context.Context, request *engine.RequestContext) (*engine.DetectionResult, error) {
	policy, _ := request.Metadata["budget_exhausted_policy"].(string)
	select {
	case p.seen <- policy:
	default:
	}
	return nil, nil
}

func TestInspectAdapterHonorsConfiguredBudgetPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy string
	}{
		{config.BudgetPolicyOpen},
		{config.BudgetPolicyObserve},
		{config.BudgetPolicyClosed},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			cfg := config.Default()
			cfg.Protection.Policy.WebAttack = config.ProtectionLevelSmart
			cfg.Sites = []config.SiteConfig{{
				ID:      "site-1",
				Name:    "adapter policy",
				Domains: []string{"policy.example"},
				Enabled: true,
				WAF: config.WAFConfig{
					Enabled:       true,
					Mode:          "block",
					ParanoiaLevel: 3,
					SemanticPolicy: config.SemanticPolicyConfig{
						BudgetExhaustedPolicy: tc.policy,
					},
				},
			}}
			probe := adapterPolicyProbe{seen: make(chan string, 1)}
			server, err := NewServer(&cfg, engine.NewPipeline(probe), noopSink{})
			if err != nil {
				t.Fatal(err)
			}
			request := adapterapi.Request{
				ContractVersion: adapterapi.Version,
				Source:          adapterapi.SourceGeneric,
				Method:          http.MethodGet,
				Path:            "/",
				Authority:       "policy.example",
				BodyState:       adapterapi.BodyStateAbsent,
			}
			if _, err := server.InspectAdapter(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-probe.seen:
				if got != tc.policy {
					t.Fatalf("adapter budget policy = %q, want %q", got, tc.policy)
				}
			default:
				t.Fatal("adapter inspection never reached the pipeline")
			}
		})
	}
}

// A concurrent protection update must not race with an in-flight inspection.
// Run with -race: the old code read s.protectionPolicy without the lock.
func TestInspectAdapterReadsProtectionPolicyUnderLock(t *testing.T) {
	cfg := config.Default()
	cfg.Sites = []config.SiteConfig{{
		ID:      "site-1",
		Name:    "race",
		Domains: []string{"race.example"},
		Enabled: true,
		WAF:     config.WAFConfig{Enabled: true, Mode: "block", ParanoiaLevel: 3},
	}}
	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	request := adapterapi.Request{
		ContractVersion: adapterapi.Version,
		Source:          adapterapi.SourceGeneric,
		Method:          http.MethodGet,
		Path:            "/",
		Authority:       "race.example",
		BodyState:       adapterapi.BodyStateAbsent,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			policy := cfg.Protection.Policy
			policy.WebAttack = config.ProtectionLevelStrict
			_ = server.UpdateProtection(config.ProtectionConfig{Policy: policy})
		}
	}()
	for i := 0; i < 50; i++ {
		if _, err := server.InspectAdapter(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
