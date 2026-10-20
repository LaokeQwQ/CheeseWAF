package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type detectionBudgetCapturePipeline struct {
	budget chan time.Duration
}

func (p detectionBudgetCapturePipeline) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	budget, _ := reqCtx.Metadata["detection_budget"].(time.Duration)
	p.budget <- budget
	return nil, nil
}

func TestProxyPassesSiteDetectionBudgetToPipeline(t *testing.T) {
	const configuredBudget = 375 * time.Millisecond
	cfg := config.Default()
	cfg.Sites[0].WAF.SemanticPolicy.DetectionBudget = configuredBudget
	cfg.Sites[0].Upstreams = []config.UpstreamConfig{{Address: "http://127.0.0.1:9000", Weight: 1}}
	if err := config.Validate(&cfg); err != nil {
		t.Fatalf("config.Validate() error = %v", err)
	}

	server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
	if err != nil {
		t.Fatal(err)
	}
	budget := make(chan time.Duration, 1)
	server.pipelineMu.Lock()
	server.pipeline = detectionBudgetCapturePipeline{budget: budget}
	server.pipelineMu.Unlock()

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))

	select {
	case got := <-budget:
		if got != configuredBudget {
			t.Fatalf("pipeline detection budget = %s, want configured site budget %s", got, configuredBudget)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not reach the detection pipeline")
	}
}
