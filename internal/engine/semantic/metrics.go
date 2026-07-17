package semantic

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Outcome labels for semantic metrics.
const (
	OutcomePass            = "pass"
	OutcomeHit             = "hit"
	OutcomeBlock           = "block"
	OutcomeBudgetExhausted = "budget_exhausted"
)

// Metrics is a process-scoped, lock-light counter set for the staged analyzer.
// Hot paths use atomics only; Snapshot takes a brief RLock for a consistent view.
type Metrics struct {
	analyzed        atomic.Uint64
	passed          atomic.Uint64
	hit             atomic.Uint64
	blocked         atomic.Uint64
	budgetExhausted atomic.Uint64
	latencySumNs    atomic.Uint64
	latencyCount    atomic.Uint64
	// latency buckets: under 50µs, 200µs, 1ms, rest
	latUnder50us  atomic.Uint64
	latUnder200us atomic.Uint64
	latUnder1ms   atomic.Uint64
	latOver1ms    atomic.Uint64

	mu         sync.RWMutex
	hitByCat   map[string]uint64
	blockByCat map[string]uint64

	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64

	allowlistPathSkips  atomic.Uint64
	allowlistParamSkips atomic.Uint64
}

// Snapshot is a point-in-time metrics view for tests, admin APIs, or Prometheus.
type Snapshot struct {
	Analyzed            uint64            `json:"analyzed"`
	Passed              uint64            `json:"passed"`
	Hit                 uint64            `json:"hit"`
	Blocked             uint64            `json:"blocked"`
	BudgetExhausted     uint64            `json:"budget_exhausted"`
	AvgLatencyNs        uint64            `json:"avg_latency_ns"`
	LatencyBuckets      map[string]uint64 `json:"latency_buckets"`
	HitByCategory       map[string]uint64 `json:"hit_by_category"`
	BlockByCategory     map[string]uint64 `json:"block_by_category"`
	CacheHits           uint64            `json:"cache_hits"`
	CacheMisses         uint64            `json:"cache_misses"`
	AllowlistPathSkips  uint64            `json:"allowlist_path_skips"`
	AllowlistParamSkips uint64            `json:"allowlist_param_skips"`
}

func NewMetrics() *Metrics {
	return &Metrics{
		hitByCat:   map[string]uint64{},
		blockByCat: map[string]uint64{},
	}
}

var processMetrics = NewMetrics()

// ProcessMetrics returns the process-wide semantic metrics instance.
func ProcessMetrics() *Metrics { return processMetrics }

// RecordAnalysis records one Analyzer.Detect completion.
// duration is wall time of the analysis; category is empty on pass.
func (m *Metrics) RecordAnalysis(duration time.Duration, outcome, category string) {
	if m == nil {
		return
	}
	m.analyzed.Add(1)
	ns := uint64(duration.Nanoseconds())
	if ns > 0 {
		m.latencySumNs.Add(ns)
		m.latencyCount.Add(1)
		switch {
		case duration < 50*time.Microsecond:
			m.latUnder50us.Add(1)
		case duration < 200*time.Microsecond:
			m.latUnder200us.Add(1)
		case duration < time.Millisecond:
			m.latUnder1ms.Add(1)
		default:
			m.latOver1ms.Add(1)
		}
	}
	switch outcome {
	case OutcomePass:
		m.passed.Add(1)
	case OutcomeHit:
		m.hit.Add(1)
		m.incCategory(category, false)
	case OutcomeBlock:
		m.hit.Add(1)
		m.blocked.Add(1)
		m.incCategory(category, true)
	}
}

// RecordBudgetExhausted increments the pipeline detection-budget counter.
func (m *Metrics) RecordBudgetExhausted() {
	if m == nil {
		return
	}
	m.budgetExhausted.Add(1)
}

// RecordCache records a candidate-cache hit or miss.
func (m *Metrics) RecordCache(hit bool) {
	if m == nil {
		return
	}
	if hit {
		m.cacheHits.Add(1)
	} else {
		m.cacheMisses.Add(1)
	}
}

// RecordAllowlistSkip records a commercial path/param allowlist skip.
// kind is "path" or "param".
func (m *Metrics) RecordAllowlistSkip(kind string) {
	if m == nil {
		return
	}
	switch strings.ToLower(kind) {
	case "path":
		m.allowlistPathSkips.Add(1)
	case "param":
		m.allowlistParamSkips.Add(1)
	}
}

func (m *Metrics) incCategory(category string, blocked bool) {
	category = normalizeCategoryKey(category)
	if category == "" {
		return
	}
	m.mu.Lock()
	if blocked {
		m.blockByCat[category]++
	} else {
		m.hitByCat[category]++
	}
	// Count block as hit for category hit map as well.
	if blocked {
		m.hitByCat[category]++
	}
	m.mu.Unlock()
}

func normalizeCategoryKey(category string) string {
	if category == "" {
		return ""
	}
	// Keep map keys small and stable.
	out := make([]byte, 0, len(category))
	for i := 0; i < len(category); i++ {
		c := category[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			out = append(out, c)
		}
	}
	return string(out)
}

// Snapshot returns a consistent copy of counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{
			LatencyBuckets:  map[string]uint64{},
			HitByCategory:   map[string]uint64{},
			BlockByCategory: map[string]uint64{},
		}
	}
	s := Snapshot{
		Analyzed:        m.analyzed.Load(),
		Passed:          m.passed.Load(),
		Hit:             m.hit.Load(),
		Blocked:         m.blocked.Load(),
		BudgetExhausted: m.budgetExhausted.Load(),
		LatencyBuckets: map[string]uint64{
			"under_50us":  m.latUnder50us.Load(),
			"under_200us": m.latUnder200us.Load(),
			"under_1ms":   m.latUnder1ms.Load(),
			"over_1ms":    m.latOver1ms.Load(),
		},
		HitByCategory:       map[string]uint64{},
		BlockByCategory:     map[string]uint64{},
		CacheHits:           m.cacheHits.Load(),
		CacheMisses:         m.cacheMisses.Load(),
		AllowlistPathSkips:  m.allowlistPathSkips.Load(),
		AllowlistParamSkips: m.allowlistParamSkips.Load(),
	}
	if n := m.latencyCount.Load(); n > 0 {
		s.AvgLatencyNs = m.latencySumNs.Load() / n
	}
	m.mu.RLock()
	for k, v := range m.hitByCat {
		s.HitByCategory[k] = v
	}
	for k, v := range m.blockByCat {
		s.BlockByCategory[k] = v
	}
	m.mu.RUnlock()
	return s
}

// ResetForTest clears counters. Tests only.
func (m *Metrics) ResetForTest() {
	if m == nil {
		return
	}
	m.analyzed.Store(0)
	m.passed.Store(0)
	m.hit.Store(0)
	m.blocked.Store(0)
	m.budgetExhausted.Store(0)
	m.latencySumNs.Store(0)
	m.latencyCount.Store(0)
	m.latUnder50us.Store(0)
	m.latUnder200us.Store(0)
	m.latUnder1ms.Store(0)
	m.latOver1ms.Store(0)
	m.cacheHits.Store(0)
	m.cacheMisses.Store(0)
	m.mu.Lock()
	m.hitByCat = map[string]uint64{}
	m.blockByCat = map[string]uint64{}
	m.mu.Unlock()
}

// SortedCategoryKeys returns stable category keys from a snapshot map.
func SortedCategoryKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
