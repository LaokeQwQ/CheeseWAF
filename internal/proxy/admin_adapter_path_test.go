package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/adapterinspect"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type adapterPathProbe struct{ seen *engine.RequestContext }

func (*adapterPathProbe) ID() string    { return "path-probe" }
func (*adapterPathProbe) Name() string  { return "path probe" }
func (*adapterPathProbe) Priority() int { return 300 }
func (p *adapterPathProbe) Detect(ctx context.Context, r *engine.RequestContext) (*engine.DetectionResult, error) {
	p.seen = r
	return (adapterBlockDetector{}).Detect(ctx, r)
}

func TestAdminAdapterEncodedPathSemantics(t *testing.T) {
	for _, branch := range []string{"Inspect", "Detect"} {
		for _, tc := range []struct {
			path, want string
			invalid    bool
		}{
			{"/docs%3Fblocked-marker", "/docs?blocked-marker", false},
			{"/docs%253Fblocked-marker", "/docs?blocked-marker", false},
			{"/docs/hello%20world", "/docs/hello world", false},
			{"/docs/hello%2520world", "/docs/hello world", false},
			{"/docs/hello world", "/docs/hello world", false},
			{"/docs%23blocked-marker", "/docs#blocked-marker", false},
			{"/docs/../blocked-marker", "/blocked-marker", false},
			{"/docs%ZZ", "", true},
			{"/docs%2500", "", true},
		} {
			t.Run(branch+tc.path, func(t *testing.T) {
				probe := &adapterPathProbe{}
				pipeline := engine.NewPipeline(probe)
				cfg := config.Default()
				cfg.Sites = []config.SiteConfig{{ID: "site-1", Domains: []string{"app.example"}, Enabled: true, WAF: config.WAFConfig{Enabled: true, Mode: "block", ParanoiaLevel: 3}}}
				cfg.Protection.Policy.WebAttack = config.ProtectionLevelStrict
				server, err := NewServer(&cfg, pipeline, noopSink{})
				if err != nil {
					t.Fatal(err)
				}
				opts := adapterinspect.Options{ResolveSite: func(string) (string, int64, bool) { return "site-1", 8 << 20, true }}
				if branch == "Inspect" {
					opts.Inspect = server.InspectAdminAdapter
				} else {
					opts.Detect = pipeline.Detect
				}
				payload, err := json.Marshal(adapterinspect.Request{ContractVersion: "v1", Authority: "app.example", Method: "GET", Path: tc.path, Query: "independent=retained%3Fvalue"})
				if err != nil {
					t.Fatal(err)
				}
				recorder := httptest.NewRecorder()
				adapterinspect.New(opts).ServeHTTP(recorder, httptest.NewRequest("POST", "/api/v1/adapter/inspect", bytes.NewReader(payload)))
				var decision adapterinspect.Decision
				if err := json.Unmarshal(recorder.Body.Bytes(), &decision); err != nil {
					t.Fatal(err)
				}
				if tc.invalid {
					if decision.StatusCode != 400 || probe.seen != nil {
						t.Fatalf("invalid path reached detection: %+v", decision)
					}
					return
				}
				if probe.seen == nil {
					t.Fatalf("pipeline not reached: %+v", decision)
				}
				if got := probe.seen.Request.URL.Path; got != tc.want {
					t.Errorf("path=%q want=%q", got, tc.want)
				}
				if got := probe.seen.NormalizedPath; got != tc.want {
					t.Errorf("normalized path=%q want=%q", got, tc.want)
				}
				if got := probe.seen.Request.URL.RawQuery; got != "independent=retained%3Fvalue" {
					t.Errorf("query=%q", got)
				}
				wantAction := "allow"
				if bytes.Contains([]byte(tc.want), []byte("blocked-marker")) {
					wantAction = "block"
				}
				if decision.Action != wantAction {
					t.Errorf("decision=%+v want action=%s", decision, wantAction)
				}
				if wantAction == "block" && decision.RuleID != "adapter-test" {
					t.Errorf("rule=%q", decision.RuleID)
				}
			})
		}
	}
}
