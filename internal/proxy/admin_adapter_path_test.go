package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	type pathCase struct {
		path, want string
		invalid    bool
	}
	cases := []pathCase{{"/文档/你好", "/文档/你好", false}}
	for c := 0; c <= 127; c++ {
		if c > 31 && c != 127 {
			continue
		}
		for _, encoded := range []string{string(rune(c)), fmt.Sprintf("%%%02X", c), fmt.Sprintf("%%25%02X", c)} {
			for _, path := range []string{"/docs/" + encoded + "marker", "/docs/" + encoded + "/../safe", "/docs/../" + encoded + "marker"} {
				cases = append(cases, pathCase{path: path, invalid: true})
			}
		}
	}
	for _, branch := range []string{"Inspect", "Detect"} {
		for _, tc := range append(cases, []pathCase{
			{"/docs%3Fblocked-marker", "/docs?blocked-marker", false},
			{"/docs%253Fblocked-marker", "/docs?blocked-marker", false},
			{"/docs/hello%20world", "/docs/hello world", false},
			{"/docs/hello%2520world", "/docs/hello world", false},
			{"/docs/hello world", "/docs/hello world", false},
			{"/docs%23blocked-marker", "/docs#blocked-marker", false},
			{"/docs/../blocked-marker", "/blocked-marker", false},
			{"/docs%ZZ", "", true},
			{"/docs%2500", "", true},
		}...) {
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
				calls := 0
				if branch == "Inspect" {
					opts.Inspect = func(ctx context.Context, req adapterinspect.Request) (adapterinspect.Decision, error) {
						calls++
						return server.InspectAdminAdapter(ctx, req)
					}
				} else {
					opts.Detect = func(ctx context.Context, req *engine.RequestContext) (*engine.DetectionResult, error) {
						calls++
						return pipeline.Detect(ctx, req)
					}
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
					if decision.Action != "block" || decision.StatusCode != 400 || calls != 0 || probe.seen != nil {
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
