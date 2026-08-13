// Package gctune provides hardware-aware, self-adjusting garbage collector
// tuning for long-running CheeseWAF processes.
//
// Go's default GC policy (GOGC=100, no memory limit) is a compromise chosen for
// unknown workloads. A WAF is not an unknown workload: it allocates a large
// number of very short-lived objects (per-request candidate slices, hit
// records, decoded buffers) and retains almost nothing between requests. That
// shape rewards a higher GOGC — fewer, larger collections — but only up to the
// point where the heap risks exceeding what the machine or container actually
// has. Guessing that point at build time is impossible, so this package
// measures it at run time.
//
// Two mechanisms are combined:
//
//  1. A hard-ish ceiling via debug.SetMemoryLimit (GOMEMLIMIT). Derived from the
//     real memory the process is allowed to use — container/cgroup limit when
//     present, physical RAM otherwise — scaled by Config.MemoryLimitRatio to
//     leave headroom for stacks, the allocator's own metadata, and non-Go
//     mappings. As the heap approaches this limit the runtime collects more
//     aggressively on its own, which is what makes a high GOGC safe.
//
//  2. A feedback loop on GOGC via debug.SetGCPercent. Every Config.Interval the
//     controller samples GC CPU cost and heap pressure from runtime/metrics and
//     nudges GOGC: up when the collector is burning CPU and there is headroom,
//     down when the live heap starts crowding the limit. Adjustments are
//     multiplicative, clamped to [MinGOGC, MaxGOGC], and gated by a dead band so
//     the loop settles instead of oscillating.
//
// Operator overrides win. If GOGC or GOMEMLIMIT is set in the environment, the
// corresponding knob is left untouched (see Config.RespectEnv): someone who
// pinned a value did so for a reason, and silently overriding it would make
// production behaviour unexplainable.
//
// The zero value of Config is not useful; call DefaultConfig and adjust.
package gctune

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metric names sampled by the controller. Declared as constants so the
// TestMetricNamesExist guard can assert the running Go toolchain still exports
// them — a silently renamed metric would otherwise degrade the controller to a
// no-op without any signal.
const (
	metricGCCPUSeconds    = "/cpu/classes/gc/total:cpu-seconds"
	metricTotalCPUSeconds = "/cpu/classes/total:cpu-seconds"
	metricHeapObjects     = "/memory/classes/heap/objects:bytes"
	metricHeapUnused      = "/memory/classes/heap/unused:bytes"
	metricHeapFree        = "/memory/classes/heap/free:bytes"
	metricTotalMapped     = "/memory/classes/total:bytes"
	metricGCCycles        = "/gc/cycles/total:gc-cycles"
)

// Config controls the tuner. Obtain a populated value from DefaultConfig.
type Config struct {
	// Enabled turns the whole package off when false. Start returns a no-op.
	Enabled bool

	// MemoryLimitRatio is the fraction of detected usable memory handed to
	// debug.SetMemoryLimit. The remainder absorbs goroutine stacks, runtime
	// metadata, and any non-Go mapping in the process. 0.75 is deliberately
	// conservative; raise it only on a dedicated host.
	MemoryLimitRatio float64

	// MinGOGC and MaxGOGC clamp the controller's output. MinGOGC guards against
	// pathological GC thrash, MaxGOGC against unbounded heap growth on a machine
	// whose real limit was mis-detected.
	MinGOGC int
	MaxGOGC int

	// BaseGOGC is the starting value. Zero means derive it from the detected
	// memory budget (see deriveBaseGOGC): more headroom, more aggressive start.
	BaseGOGC int

	// TargetGCCPUFraction is the GC CPU budget, as a fraction of total process
	// CPU, that the controller aims to stay under. Exceeding it while heap
	// pressure is low is the signal to raise GOGC. 0.05 keeps the collector to
	// roughly a twentieth of the CPU bill.
	TargetGCCPUFraction float64

	// HeapPressureHigh is the live-heap-to-memory-limit ratio above which the
	// controller lowers GOGC regardless of CPU cost. This is the safety side of
	// the loop and takes precedence over the CPU objective.
	HeapPressureHigh float64

	// HeapPressureLow is the ratio below which raising GOGC is considered safe.
	// The gap between Low and High is the dead band that stops oscillation.
	HeapPressureLow float64

	// Interval is the controller's sampling period. Shorter reacts faster but
	// samples noisier deltas; below a second the CPU-fraction delta is mostly
	// measurement error.
	Interval time.Duration

	// StepUp and StepDown are the multiplicative adjustment factors applied to
	// GOGC. Down is intentionally more decisive than up is generous: growing the
	// heap slowly and shrinking it quickly is the safe asymmetry.
	StepUp   float64
	StepDown float64

	// RespectEnv leaves GOGC alone when the GOGC environment variable is set,
	// and leaves the memory limit alone when GOMEMLIMIT is set.
	RespectEnv bool

	// Logf receives one line per applied adjustment and one line at startup.
	// Nil disables logging. Keep it cheap; it runs on the controller goroutine.
	Logf func(format string, args ...any)
}

// DefaultConfig returns the tuning profile used by the WAF: allocation-heavy,
// short-lived objects, latency-sensitive, unknown deployment size.
func DefaultConfig() Config {
	return Config{
		Enabled:             true,
		MemoryLimitRatio:    0.75,
		MinGOGC:             50,
		MaxGOGC:             400,
		BaseGOGC:            0,
		TargetGCCPUFraction: 0.05,
		HeapPressureHigh:    0.70,
		HeapPressureLow:     0.45,
		Interval:            30 * time.Second,
		StepUp:              1.25,
		StepDown:            0.75,
		RespectEnv:          true,
		Logf:                nil,
	}
}

func (c Config) validate() error {
	var errs []error
	if c.MemoryLimitRatio <= 0 || c.MemoryLimitRatio > 1 {
		errs = append(errs, fmt.Errorf("MemoryLimitRatio must be in (0,1], got %v", c.MemoryLimitRatio))
	}
	if c.MinGOGC < 1 {
		errs = append(errs, fmt.Errorf("MinGOGC must be >= 1, got %d", c.MinGOGC))
	}
	if c.MaxGOGC < c.MinGOGC {
		errs = append(errs, fmt.Errorf("MaxGOGC (%d) must be >= MinGOGC (%d)", c.MaxGOGC, c.MinGOGC))
	}
	if c.BaseGOGC != 0 && (c.BaseGOGC < c.MinGOGC || c.BaseGOGC > c.MaxGOGC) {
		errs = append(errs, fmt.Errorf("BaseGOGC (%d) must be 0 or within [%d,%d]", c.BaseGOGC, c.MinGOGC, c.MaxGOGC))
	}
	if c.TargetGCCPUFraction <= 0 || c.TargetGCCPUFraction >= 1 {
		errs = append(errs, fmt.Errorf("TargetGCCPUFraction must be in (0,1), got %v", c.TargetGCCPUFraction))
	}
	if c.HeapPressureHigh <= 0 || c.HeapPressureHigh >= 1 {
		errs = append(errs, fmt.Errorf("HeapPressureHigh must be in (0,1), got %v", c.HeapPressureHigh))
	}
	if c.HeapPressureLow <= 0 || c.HeapPressureLow >= c.HeapPressureHigh {
		errs = append(errs, fmt.Errorf("HeapPressureLow (%v) must be in (0,HeapPressureHigh=%v)", c.HeapPressureLow, c.HeapPressureHigh))
	}
	if c.Interval < time.Second {
		errs = append(errs, fmt.Errorf("Interval must be >= 1s, got %v", c.Interval))
	}
	if c.StepUp <= 1 {
		errs = append(errs, fmt.Errorf("StepUp must be > 1, got %v", c.StepUp))
	}
	if c.StepDown <= 0 || c.StepDown >= 1 {
		errs = append(errs, fmt.Errorf("StepDown must be in (0,1), got %v", c.StepDown))
	}
	return errors.Join(errs...)
}

// Snapshot is an observable view of controller state, suitable for exposing on
// an admin endpoint or scraping into metrics.
type Snapshot struct {
	Enabled bool `json:"enabled"`

	// MemoryBudget is the usable memory detected for this process.
	MemoryBudget uint64 `json:"memory_budget_bytes"`
	// MemorySource records how MemoryBudget was determined, e.g.
	// "cgroup-v2", "windows-job-object", "sysctl-hw.memsize".
	MemorySource string `json:"memory_source"`
	// MemoryLimit is the value passed to debug.SetMemoryLimit, or 0 when the
	// limit was left to the operator/runtime.
	MemoryLimit int64 `json:"memory_limit_bytes"`

	GOGC        int `json:"gogc"`
	InitialGOGC int `json:"initial_gogc"`
	NumCPU      int `json:"num_cpu"`
	GOMAXPROCS  int `json:"gomaxprocs"`

	// Adjustments counts applied GOGC changes since Start.
	Adjustments uint64 `json:"adjustments"`
	// LastGCCPUFraction and LastHeapPressure are the most recent samples.
	LastGCCPUFraction float64 `json:"last_gc_cpu_fraction"`
	LastHeapPressure  float64 `json:"last_heap_pressure"`
	LastAdjustReason  string  `json:"last_adjust_reason"`

	// GOGCPinnedByEnv and MemLimitPinnedByEnv report operator overrides that
	// caused the tuner to leave a knob alone.
	GOGCPinnedByEnv     bool `json:"gogc_pinned_by_env"`
	MemLimitPinnedByEnv bool `json:"memlimit_pinned_by_env"`
}

// Tuner owns the controller goroutine and the sampling state it needs to turn
// cumulative runtime counters into per-interval rates.
type Tuner struct {
	cfg Config

	mu    sync.Mutex
	state Snapshot

	samples     []metrics.Sample
	sampleIndex map[string]int

	prevGCCPU    float64
	prevTotalCPU float64
	prevValid    bool

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// Start detects the memory budget, applies the initial GOGC and memory limit,
// and launches the controller goroutine. The returned Tuner is always non-nil;
// Stop is safe to call on it even when tuning is disabled or setup failed.
//
// An error is returned only for an invalid Config. Detection failures are not
// errors: the tuner degrades to leaving the runtime at its defaults and records
// the reason in Snapshot.
func Start(cfg Config) (*Tuner, error) {
	t := &Tuner{
		cfg:  cfg,
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if !cfg.Enabled {
		close(t.done)
		t.state.Enabled = false
		t.state.NumCPU = runtime.NumCPU()
		t.state.GOMAXPROCS = runtime.GOMAXPROCS(0)
		t.state.GOGC = currentGOGC()
		t.state.InitialGOGC = t.state.GOGC
		t.state.LastAdjustReason = "disabled"
		return t, nil
	}
	if err := cfg.validate(); err != nil {
		close(t.done)
		return t, fmt.Errorf("gctune: invalid config: %w", err)
	}

	t.initSamples()

	budget, source := DetectMemoryBudget()
	t.state.Enabled = true
	t.state.MemoryBudget = budget
	t.state.MemorySource = source
	t.state.NumCPU = runtime.NumCPU()
	t.state.GOMAXPROCS = runtime.GOMAXPROCS(0)

	_, gogcPinned := os.LookupEnv("GOGC")
	_, memPinned := os.LookupEnv("GOMEMLIMIT")
	if !cfg.RespectEnv {
		gogcPinned, memPinned = false, false
	}
	t.state.GOGCPinnedByEnv = gogcPinned
	t.state.MemLimitPinnedByEnv = memPinned

	// Memory limit first: it is what makes a raised GOGC safe, so it must be in
	// place before GOGC goes up.
	if !memPinned && budget > 0 {
		limit := int64(float64(budget) * cfg.MemoryLimitRatio)
		if limit > 0 {
			debug.SetMemoryLimit(limit)
			t.state.MemoryLimit = limit
		}
	} else if memPinned {
		// Read back whatever the operator set so heap pressure is computed
		// against the limit actually in force.
		t.state.MemoryLimit = debug.SetMemoryLimit(-1)
	}

	base := cfg.BaseGOGC
	if base == 0 {
		base = deriveBaseGOGC(budget, cfg)
	}
	base = clampInt(base, cfg.MinGOGC, cfg.MaxGOGC)
	if !gogcPinned {
		debug.SetGCPercent(base)
		t.state.GOGC = base
	} else {
		t.state.GOGC = currentGOGC()
	}
	t.state.InitialGOGC = t.state.GOGC
	t.state.LastAdjustReason = "initial"

	t.logf("gctune: start budget=%s source=%s memlimit=%s gogc=%d (env_pinned gogc=%v memlimit=%v) gomaxprocs=%d",
		humanBytes(budget), source, humanBytesSigned(t.state.MemoryLimit), t.state.GOGC,
		gogcPinned, memPinned, t.state.GOMAXPROCS)

	go t.run()
	return t, nil
}

// Stop halts the controller and waits for it to exit. Safe to call multiple
// times and safe on a Tuner returned alongside an error.
func (t *Tuner) Stop() {
	t.stopOnce.Do(func() { close(t.stop) })
	<-t.done
}

// Snapshot returns a copy of the current controller state.
func (t *Tuner) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

func (t *Tuner) run() {
	defer close(t.done)
	ticker := time.NewTicker(t.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			t.tick()
		}
	}
}

func (t *Tuner) initSamples() {
	names := []string{
		metricGCCPUSeconds,
		metricTotalCPUSeconds,
		metricHeapObjects,
		metricHeapUnused,
		metricHeapFree,
		metricTotalMapped,
		metricGCCycles,
	}
	t.samples = make([]metrics.Sample, len(names))
	t.sampleIndex = make(map[string]int, len(names))
	for i, n := range names {
		t.samples[i].Name = n
		t.sampleIndex[n] = i
	}
}

// reading is one decoded sample set. Fields are zero when the corresponding
// metric is unsupported by the running toolchain.
type reading struct {
	gcCPU      float64
	totalCPU   float64
	heapLive   uint64
	heapMapped uint64
	gcCycles   uint64
	ok         bool
}

func (t *Tuner) sample() reading {
	metrics.Read(t.samples)
	var r reading
	float := func(name string) (float64, bool) {
		s := t.samples[t.sampleIndex[name]]
		if s.Value.Kind() != metrics.KindFloat64 {
			return 0, false
		}
		return s.Value.Float64(), true
	}
	uint := func(name string) (uint64, bool) {
		s := t.samples[t.sampleIndex[name]]
		if s.Value.Kind() != metrics.KindUint64 {
			return 0, false
		}
		return s.Value.Uint64(), true
	}

	gcCPU, ok1 := float(metricGCCPUSeconds)
	totalCPU, ok2 := float(metricTotalCPUSeconds)
	heapObjects, ok3 := uint(metricHeapObjects)
	// Live heap is approximated by objects + unused spans: that is the memory the
	// allocator is actually holding for the heap, which is what GOMEMLIMIT
	// governs. Free-but-mapped memory is excluded because the runtime can return
	// it to the OS under pressure.
	heapUnused, _ := uint(metricHeapUnused)
	mapped, _ := uint(metricTotalMapped)
	cycles, _ := uint(metricGCCycles)

	r.gcCPU = gcCPU
	r.totalCPU = totalCPU
	r.heapLive = heapObjects + heapUnused
	r.heapMapped = mapped
	r.gcCycles = cycles
	r.ok = ok1 && ok2 && ok3
	return r
}

func (t *Tuner) tick() {
	r := t.sample()
	if !r.ok {
		// Metrics unavailable: hold position rather than guess.
		t.mu.Lock()
		t.state.LastAdjustReason = "metrics-unavailable"
		t.mu.Unlock()
		return
	}

	gcFraction, haveFraction := t.gcCPUFraction(r)

	t.mu.Lock()
	limit := t.state.MemoryLimit
	gogc := t.state.GOGC
	pinned := t.state.GOGCPinnedByEnv
	t.mu.Unlock()

	pressure := heapPressure(r.heapLive, limit)

	next, reason := t.decide(gogc, gcFraction, haveFraction, pressure)

	t.mu.Lock()
	t.state.LastGCCPUFraction = gcFraction
	t.state.LastHeapPressure = pressure
	if pinned {
		t.state.LastAdjustReason = "gogc-pinned-by-env"
		t.mu.Unlock()
		return
	}
	changed := next != gogc
	if changed {
		t.state.GOGC = next
		t.state.Adjustments++
	}
	t.state.LastAdjustReason = reason
	t.mu.Unlock()

	if changed {
		debug.SetGCPercent(next)
		t.logf("gctune: gogc %d -> %d reason=%s gc_cpu=%.3f%% heap_pressure=%.1f%% heap_live=%s limit=%s",
			gogc, next, reason, gcFraction*100, pressure*100,
			humanBytes(r.heapLive), humanBytesSigned(limit))
	}
}

// gcCPUFraction converts cumulative CPU counters into the fraction of CPU spent
// in GC since the previous tick. The first call establishes the baseline and
// reports no reading, because a fraction computed against process start would
// be dominated by startup and would never reflect current load.
func (t *Tuner) gcCPUFraction(r reading) (float64, bool) {
	defer func() {
		t.prevGCCPU = r.gcCPU
		t.prevTotalCPU = r.totalCPU
		t.prevValid = true
	}()
	if !t.prevValid {
		return 0, false
	}
	dGC := r.gcCPU - t.prevGCCPU
	dTotal := r.totalCPU - t.prevTotalCPU
	// Counters are monotonic; a negative delta means a reset or a wrapped
	// sample, so discard it instead of producing a nonsense ratio.
	if dGC < 0 || dTotal <= 0 {
		return 0, false
	}
	f := dGC / dTotal
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	return f, true
}

// decide is the control law, factored out so it can be unit-tested without a
// live runtime. Safety (heap pressure) is evaluated before throughput (GC CPU).
func (t *Tuner) decide(gogc int, gcFraction float64, haveFraction bool, pressure float64) (int, string) {
	cfg := t.cfg

	// Safety first: crowding the memory limit means lower GOGC, whatever the CPU
	// cost. Running out of memory is not a performance trade-off.
	if pressure >= cfg.HeapPressureHigh {
		next := clampInt(scaleInt(gogc, cfg.StepDown), cfg.MinGOGC, cfg.MaxGOGC)
		if next == gogc {
			return gogc, "heap-pressure-high-at-min"
		}
		return next, "heap-pressure-high"
	}

	if !haveFraction {
		return gogc, "baseline-sample"
	}

	// Throughput: the collector is over budget and there is room to grow, so
	// trade memory for CPU.
	if gcFraction > cfg.TargetGCCPUFraction && pressure < cfg.HeapPressureLow {
		next := clampInt(scaleInt(gogc, cfg.StepUp), cfg.MinGOGC, cfg.MaxGOGC)
		if next == gogc {
			return gogc, "gc-cpu-high-at-max"
		}
		return next, "gc-cpu-high"
	}

	// Give memory back when the collector is cheap and GOGC sits above the
	// starting point: a quiet process should not hold an inflated heap forever,
	// because the next traffic spike needs that headroom.
	halfTarget := cfg.TargetGCCPUFraction / 2
	if gcFraction < halfTarget && gogc > t.initialGOGC() && pressure < cfg.HeapPressureLow {
		next := clampInt(scaleInt(gogc, cfg.StepDown), t.initialGOGC(), cfg.MaxGOGC)
		if next == gogc {
			return gogc, "gc-cpu-low-at-base"
		}
		return next, "gc-cpu-low-reclaim"
	}

	return gogc, "steady"
}

func (t *Tuner) initialGOGC() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state.InitialGOGC
}

func (t *Tuner) logf(format string, args ...any) {
	if t.cfg.Logf == nil {
		return
	}
	t.cfg.Logf(format, args...)
}

// heapPressure is live heap as a fraction of the memory limit. Zero when no
// limit is in force, which disables the pressure arm of the controller — with
// no ceiling there is no meaningful notion of "too close to it".
func heapPressure(heapLive uint64, limit int64) float64 {
	if limit <= 0 || heapLive == 0 {
		return 0
	}
	// math.MaxInt64 is the runtime's sentinel for "no limit".
	if limit == math.MaxInt64 {
		return 0
	}
	return float64(heapLive) / float64(limit)
}

// deriveBaseGOGC picks a starting GOGC from the memory budget. Small budgets
// stay near the Go default because there is no room to trade; large budgets
// start higher because the WAF's garbage is overwhelmingly short-lived and
// collecting it eagerly is wasted work.
func deriveBaseGOGC(budget uint64, cfg Config) int {
	const gib = 1 << 30
	switch {
	case budget == 0:
		return 100 // detection failed: do not deviate from the Go default
	case budget < 512<<20:
		return 75
	case budget < 2*gib:
		return 100
	case budget < 8*gib:
		return 150
	case budget < 32*gib:
		return 200
	default:
		return 250
	}
}

// currentGOGC reads the live GOGC without permanently changing it:
// SetGCPercent returns the previous value, so setting it back restores state.
func currentGOGC() int {
	prev := debug.SetGCPercent(100)
	debug.SetGCPercent(prev)
	return prev
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// scaleInt multiplies and rounds, guaranteeing movement of at least one unit in
// the intended direction so a small GOGC cannot get stuck by rounding.
func scaleInt(v int, factor float64) int {
	out := int(math.Round(float64(v) * factor))
	if factor > 1 && out <= v {
		return v + 1
	}
	if factor < 1 && out >= v {
		return v - 1
	}
	return out
}

func humanBytes(b uint64) string {
	if b == 0 {
		return "unknown"
	}
	const unit = 1024
	if b < unit {
		return strconv.FormatUint(b, 10) + "B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	f := float64(b)
	i := -1
	for f >= unit && i < len(units)-1 {
		f /= unit
		i++
	}
	return strings.TrimSuffix(strconv.FormatFloat(f, 'f', 1, 64), ".0") + units[i]
}

func humanBytesSigned(b int64) string {
	if b <= 0 {
		return "unset"
	}
	if b == math.MaxInt64 {
		return "unlimited"
	}
	return humanBytes(uint64(b))
}
