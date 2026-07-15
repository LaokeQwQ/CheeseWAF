package semantic

import (
	"sync"
	"testing"
	"time"
)

func TestMetricsRecordAndSnapshot(t *testing.T) {
	m := NewMetrics()
	m.RecordAnalysis(30*time.Microsecond, OutcomePass, "")
	m.RecordAnalysis(100*time.Microsecond, OutcomeBlock, "sqli")
	m.RecordAnalysis(2*time.Millisecond, OutcomeHit, "xss")
	m.RecordBudgetExhausted()
	m.RecordAllowlistSkip("path")
	m.RecordAllowlistSkip("param")
	m.RecordAllowlistSkip("param")

	s := m.Snapshot()
	if s.Analyzed != 3 || s.Passed != 1 || s.Hit != 2 || s.Blocked != 1 || s.BudgetExhausted != 1 {
		t.Fatalf("unexpected totals: %+v", s)
	}
	if s.AllowlistPathSkips != 1 || s.AllowlistParamSkips != 2 {
		t.Fatalf("unexpected allowlist skips: path=%d param=%d", s.AllowlistPathSkips, s.AllowlistParamSkips)
	}
	if s.HitByCategory["sqli"] != 1 || s.BlockByCategory["sqli"] != 1 {
		t.Fatalf("category counters: hit=%v block=%v", s.HitByCategory, s.BlockByCategory)
	}
	if s.LatencyBuckets["under_50us"] != 1 || s.LatencyBuckets["under_200us"] != 1 || s.LatencyBuckets["over_1ms"] != 1 {
		t.Fatalf("latency buckets: %+v", s.LatencyBuckets)
	}
	if s.AvgLatencyNs == 0 {
		t.Fatal("expected average latency")
	}
}

func TestMetricsConcurrentRecord(t *testing.T) {
	m := NewMetrics()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if j%5 == 0 {
					m.RecordAnalysis(time.Microsecond, OutcomeBlock, "sqli")
				} else {
					m.RecordAnalysis(time.Microsecond, OutcomePass, "")
				}
			}
		}(i)
	}
	wg.Wait()
	s := m.Snapshot()
	if s.Analyzed != 3200 {
		t.Fatalf("analyzed=%d", s.Analyzed)
	}
	if s.Blocked != 640 || s.Passed != 2560 {
		t.Fatalf("blocked=%d passed=%d", s.Blocked, s.Passed)
	}
}
