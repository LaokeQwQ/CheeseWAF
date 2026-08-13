package gctune

import (
	"math"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"
)

// restoreGC snapshots and restores the process-wide GC knobs. Every test that
// calls into the runtime must use it: leaking a GOGC of 400 or a tiny memory
// limit into sibling tests would make unrelated failures look flaky.
func restoreGC(t *testing.T) {
	t.Helper()
	prevGOGC := debug.SetGCPercent(100)
	debug.SetGCPercent(prevGOGC)
	prevLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(prevGOGC)
		debug.SetMemoryLimit(prevLimit)
	})
}

func TestMetricNamesExist(t *testing.T) {
	// The controller degrades to a no-op if a metric name disappears, and it does
	// so silently. This test is the tripwire for a toolchain upgrade renaming one.
	all := metrics.All()
	have := make(map[string]bool, len(all))
	for _, d := range all {
		have[d.Name] = true
	}
	required := []string{
		metricGCCPUSeconds,
		metricTotalCPUSeconds,
		metricHeapObjects,
		metricHeapUnused,
		metricHeapFree,
		metricTotalMapped,
		metricGCCycles,
	}
	for _, name := range required {
		if !have[name] {
			t.Errorf("runtime/metrics no longer exports %q (Go %s): the controller would silently stop adjusting", name, runtime.Version())
		}
	}
}

func TestSampleReadsLiveMetrics(t *testing.T) {
	tn := &Tuner{cfg: DefaultConfig()}
	tn.initSamples()

	// Force allocation so the heap has a nonzero live set to report.
	sink := make([][]byte, 0, 64)
	for i := 0; i < 64; i++ {
		sink = append(sink, make([]byte, 4096))
	}
	runtime.GC()
	r := tn.sample()
	if !r.ok {
		t.Fatalf("sample not ok: metrics unavailable on %s", runtime.Version())
	}
	if r.heapLive == 0 {
		t.Error("heapLive == 0 with a live heap")
	}
	if r.totalCPU <= 0 {
		t.Error("totalCPU <= 0")
	}
	if r.gcCycles == 0 {
		t.Error("gcCycles == 0 after an explicit runtime.GC()")
	}
	runtime.KeepAlive(sink)
}

func TestGCCPUFractionFirstSampleIsBaseline(t *testing.T) {
	tn := &Tuner{cfg: DefaultConfig()}
	tn.initSamples()

	// First reading has nothing to diff against; reporting a fraction here would
	// measure process startup, not current load.
	if _, ok := tn.gcCPUFraction(reading{gcCPU: 1, totalCPU: 10}); ok {
		t.Error("first sample reported a usable fraction; must be baseline-only")
	}
	f, ok := tn.gcCPUFraction(reading{gcCPU: 2, totalCPU: 30})
	if !ok {
		t.Fatal("second sample did not report a fraction")
	}
	// dGC=1, dTotal=20 => 0.05
	if math.Abs(f-0.05) > 1e-9 {
		t.Errorf("fraction = %v, want 0.05", f)
	}
}

func TestGCCPUFractionRejectsNonMonotonicCounters(t *testing.T) {
	tn := &Tuner{cfg: DefaultConfig()}
	tn.initSamples()
	tn.gcCPUFraction(reading{gcCPU: 5, totalCPU: 100})

	if _, ok := tn.gcCPUFraction(reading{gcCPU: 4, totalCPU: 120}); ok {
		t.Error("accepted a decreasing GC counter")
	}
	// Re-baseline, then a stalled total: dTotal == 0 must not divide.
	tn.gcCPUFraction(reading{gcCPU: 10, totalCPU: 200})
	if _, ok := tn.gcCPUFraction(reading{gcCPU: 11, totalCPU: 200}); ok {
		t.Error("accepted a zero total-CPU delta")
	}
}

func TestGCCPUFractionClampsToUnitInterval(t *testing.T) {
	tn := &Tuner{cfg: DefaultConfig()}
	tn.initSamples()
	tn.gcCPUFraction(reading{gcCPU: 0, totalCPU: 0.0001})
	// GC CPU exceeding total CPU is physically impossible but arithmetically
	// reachable across a sampling race; it must clamp, not report >1.
	f, ok := tn.gcCPUFraction(reading{gcCPU: 100, totalCPU: 0.0002})
	if !ok {
		t.Fatal("no fraction reported")
	}
	if f > 1 {
		t.Errorf("fraction = %v, want <= 1", f)
	}
}

func TestDecideSafetyBeatsThroughput(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 200

	// High heap pressure AND high GC CPU: the pressure arm must win, because
	// raising GOGC here trades an OOM for a CPU saving.
	next, reason := tn.decide(200, 0.90, true, cfg.HeapPressureHigh+0.05)
	if next >= 200 {
		t.Errorf("GOGC %d did not decrease under high pressure (reason=%s)", next, reason)
	}
	if reason != "heap-pressure-high" {
		t.Errorf("reason = %q, want heap-pressure-high", reason)
	}
}

func TestDecideRaisesGOGCWhenGCExpensiveAndHeapRoomy(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 100

	next, reason := tn.decide(100, cfg.TargetGCCPUFraction*3, true, 0.10)
	if next <= 100 {
		t.Errorf("GOGC %d did not increase when GC CPU was over budget (reason=%s)", next, reason)
	}
	if reason != "gc-cpu-high" {
		t.Errorf("reason = %q, want gc-cpu-high", reason)
	}
}

func TestDecideHoldsInDeadBand(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 150

	// Pressure between Low and High is the dead band: neither arm may fire, or
	// the controller oscillates instead of settling.
	mid := (cfg.HeapPressureLow + cfg.HeapPressureHigh) / 2
	next, reason := tn.decide(150, cfg.TargetGCCPUFraction*3, true, mid)
	if next != 150 {
		t.Errorf("GOGC moved to %d inside the dead band (reason=%s)", next, reason)
	}
	if reason != "steady" {
		t.Errorf("reason = %q, want steady", reason)
	}
}

func TestDecideReclaimsInflatedHeapWhenQuiet(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 100

	// Cheap GC and GOGC well above the baseline: hand memory back so the next
	// traffic spike has headroom.
	next, reason := tn.decide(300, cfg.TargetGCCPUFraction/10, true, 0.05)
	if next >= 300 {
		t.Errorf("GOGC %d was not reclaimed while idle (reason=%s)", next, reason)
	}
	if reason != "gc-cpu-low-reclaim" {
		t.Errorf("reason = %q, want gc-cpu-low-reclaim", reason)
	}
	// Reclaim must never undercut the starting point.
	if next < 100 {
		t.Errorf("GOGC %d fell below InitialGOGC=100", next)
	}
}

func TestDecideNeverReclaimsBelowInitial(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 200

	next, reason := tn.decide(200, 0, true, 0.01)
	if next != 200 {
		t.Errorf("GOGC = %d at baseline with cheap GC, want unchanged (reason=%s)", next, reason)
	}
}

func TestDecideRespectsClamps(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinGOGC = 50
	cfg.MaxGOGC = 400
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 50

	atMax, reason := tn.decide(400, cfg.TargetGCCPUFraction*5, true, 0.01)
	if atMax != 400 {
		t.Errorf("GOGC = %d, want clamped at MaxGOGC=400", atMax)
	}
	if reason != "gc-cpu-high-at-max" {
		t.Errorf("reason = %q, want gc-cpu-high-at-max", reason)
	}

	atMin, reason := tn.decide(50, 0.9, true, 0.99)
	if atMin != 50 {
		t.Errorf("GOGC = %d, want clamped at MinGOGC=50", atMin)
	}
	if reason != "heap-pressure-high-at-min" {
		t.Errorf("reason = %q, want heap-pressure-high-at-min", reason)
	}
}

func TestDecideHoldsOnBaselineSample(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 100
	next, reason := tn.decide(100, 0, false, 0.10)
	if next != 100 {
		t.Errorf("GOGC moved to %d without a usable CPU fraction", next)
	}
	if reason != "baseline-sample" {
		t.Errorf("reason = %q, want baseline-sample", reason)
	}
}

// TestDecideConvergesUnderSustainedPressure walks the control law forward to
// confirm it reaches a fixed point instead of ringing. A controller that
// oscillates between two GOGC values forever would keep calling SetGCPercent and
// keep changing collection behaviour under steady load.
func TestDecideConvergesUnderSustainedPressure(t *testing.T) {
	cfg := DefaultConfig()
	tn := &Tuner{cfg: cfg}
	tn.state.InitialGOGC = 100

	gogc := 100
	seen := map[int]int{}
	for i := 0; i < 100; i++ {
		next, _ := tn.decide(gogc, cfg.TargetGCCPUFraction*4, true, 0.10)
		if next == gogc {
			break
		}
		gogc = next
		seen[gogc]++
		if seen[gogc] > 2 {
			t.Fatalf("GOGC %d revisited %d times: controller is oscillating", gogc, seen[gogc])
		}
	}
	if gogc != cfg.MaxGOGC {
		t.Errorf("converged at GOGC=%d, want MaxGOGC=%d under sustained over-budget GC", gogc, cfg.MaxGOGC)
	}
}

func TestHeapPressure(t *testing.T) {
	cases := []struct {
		name  string
		live  uint64
		limit int64
		want  float64
	}{
		{"no limit", 1 << 30, 0, 0},
		{"negative limit", 1 << 30, -1, 0},
		{"runtime sentinel means unlimited", 1 << 30, math.MaxInt64, 0},
		{"empty heap", 0, 1 << 30, 0},
		{"half", 512 << 20, 1 << 30, 0.5},
		{"over limit reports above 1", 2 << 30, 1 << 30, 2.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := heapPressure(tc.live, tc.limit)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("heapPressure(%d, %d) = %v, want %v", tc.live, tc.limit, got, tc.want)
			}
		})
	}
}

func TestScaleIntAlwaysMoves(t *testing.T) {
	// Rounding must not strand a small GOGC: scaling 1 by 1.25 rounds to 1, which
	// would make the controller unable to ever raise it.
	if got := scaleInt(1, 1.25); got <= 1 {
		t.Errorf("scaleInt(1, 1.25) = %d, want > 1", got)
	}
	if got := scaleInt(2, 0.75); got >= 2 {
		t.Errorf("scaleInt(2, 0.75) = %d, want < 2", got)
	}
	if got := scaleInt(100, 1.25); got != 125 {
		t.Errorf("scaleInt(100, 1.25) = %d, want 125", got)
	}
	if got := scaleInt(100, 0.75); got != 75 {
		t.Errorf("scaleInt(100, 0.75) = %d, want 75", got)
	}
}

func TestClampInt(t *testing.T) {
	if got := clampInt(5, 10, 20); got != 10 {
		t.Errorf("clampInt(5,10,20) = %d, want 10", got)
	}
	if got := clampInt(25, 10, 20); got != 20 {
		t.Errorf("clampInt(25,10,20) = %d, want 20", got)
	}
	if got := clampInt(15, 10, 20); got != 15 {
		t.Errorf("clampInt(15,10,20) = %d, want 15", got)
	}
}

func TestDeriveBaseGOGCScalesWithBudget(t *testing.T) {
	cfg := DefaultConfig()
	const gib = 1 << 30

	// Undetected budget must not deviate from the Go default: with no knowledge
	// of the ceiling, raising GOGC is gambling with an OOM.
	if got := deriveBaseGOGC(0, cfg); got != 100 {
		t.Errorf("deriveBaseGOGC(0) = %d, want 100 (Go default)", got)
	}

	small := deriveBaseGOGC(256<<20, cfg)
	medium := deriveBaseGOGC(4*gib, cfg)
	large := deriveBaseGOGC(64*gib, cfg)
	if !(small < medium && medium < large) {
		t.Errorf("base GOGC not monotonic in budget: 256MiB=%d 4GiB=%d 64GiB=%d", small, medium, large)
	}
	if small >= 100 {
		t.Errorf("deriveBaseGOGC(256MiB) = %d, want < 100 on a memory-constrained host", small)
	}
}

func TestConfigValidate(t *testing.T) {
	valid := DefaultConfig()
	if err := valid.validate(); err != nil {
		t.Fatalf("DefaultConfig is invalid: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"ratio zero", func(c *Config) { c.MemoryLimitRatio = 0 }, "MemoryLimitRatio"},
		{"ratio above one", func(c *Config) { c.MemoryLimitRatio = 1.5 }, "MemoryLimitRatio"},
		{"min below one", func(c *Config) { c.MinGOGC = 0 }, "MinGOGC"},
		{"max below min", func(c *Config) { c.MinGOGC, c.MaxGOGC = 200, 100 }, "MaxGOGC"},
		{"base out of range", func(c *Config) { c.BaseGOGC = 10000 }, "BaseGOGC"},
		{"target fraction one", func(c *Config) { c.TargetGCCPUFraction = 1 }, "TargetGCCPUFraction"},
		{"pressure high one", func(c *Config) { c.HeapPressureHigh = 1 }, "HeapPressureHigh"},
		{"pressure low above high", func(c *Config) { c.HeapPressureLow = 0.9; c.HeapPressureHigh = 0.5 }, "HeapPressureLow"},
		{"interval too short", func(c *Config) { c.Interval = time.Millisecond }, "Interval"},
		{"step up not above one", func(c *Config) { c.StepUp = 1 }, "StepUp"},
		{"step down above one", func(c *Config) { c.StepDown = 1.5 }, "StepDown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mutate(&cfg)
			err := cfg.validate()
			if err == nil {
				t.Fatalf("validate() = nil, want an error mentioning %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("validate() = %v, want mention of %s", err, tc.want)
			}
		})
	}
}

func TestStartRejectsInvalidConfigWithoutTouchingRuntime(t *testing.T) {
	restoreGC(t)
	before := currentGOGC()

	cfg := DefaultConfig()
	cfg.MinGOGC = 0
	tn, err := Start(cfg)
	if err == nil {
		t.Fatal("Start accepted an invalid config")
	}
	if tn == nil {
		t.Fatal("Start returned a nil Tuner alongside an error; Stop would panic")
	}
	if after := currentGOGC(); after != before {
		t.Errorf("GOGC changed from %d to %d despite config rejection", before, after)
	}
	tn.Stop() // must not hang or panic
}

func TestStartDisabledIsNoOp(t *testing.T) {
	restoreGC(t)
	before := currentGOGC()

	cfg := DefaultConfig()
	cfg.Enabled = false
	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start(disabled) returned error: %v", err)
	}
	defer tn.Stop()

	if after := currentGOGC(); after != before {
		t.Errorf("GOGC changed from %d to %d while disabled", before, after)
	}
	snap := tn.Snapshot()
	if snap.Enabled {
		t.Error("Snapshot reports Enabled while disabled")
	}
	if snap.LastAdjustReason != "disabled" {
		t.Errorf("LastAdjustReason = %q, want disabled", snap.LastAdjustReason)
	}
	if snap.MemoryLimit != 0 {
		t.Errorf("MemoryLimit = %d, want 0 while disabled", snap.MemoryLimit)
	}
}

func TestStartAppliesLimitAndGOGC(t *testing.T) {
	restoreGC(t)

	var mu sync.Mutex
	var logs []string
	cfg := DefaultConfig()
	cfg.RespectEnv = false // exercise the apply path regardless of the CI environment
	cfg.Interval = time.Second
	cfg.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, format)
	}

	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tn.Stop()

	snap := tn.Snapshot()
	if !snap.Enabled {
		t.Error("Snapshot reports disabled after a successful Start")
	}
	if snap.GOGC < cfg.MinGOGC || snap.GOGC > cfg.MaxGOGC {
		t.Errorf("GOGC = %d, outside [%d,%d]", snap.GOGC, cfg.MinGOGC, cfg.MaxGOGC)
	}
	if snap.InitialGOGC != snap.GOGC {
		t.Errorf("InitialGOGC = %d, GOGC = %d; want equal immediately after Start", snap.InitialGOGC, snap.GOGC)
	}
	if got := currentGOGC(); got != snap.GOGC {
		t.Errorf("runtime GOGC = %d, Snapshot says %d", got, snap.GOGC)
	}
	if snap.NumCPU != runtime.NumCPU() {
		t.Errorf("NumCPU = %d, want %d", snap.NumCPU, runtime.NumCPU())
	}

	// This platform must be able to detect memory; a silent fall-through to
	// "undetected" would disable the safety arm of the controller entirely.
	if snap.MemoryBudget == 0 {
		t.Errorf("MemoryBudget = 0 (source=%q) on %s/%s: detection regressed",
			snap.MemorySource, runtime.GOOS, runtime.GOARCH)
	}
	if snap.MemoryLimit <= 0 {
		t.Errorf("MemoryLimit = %d, want > 0 with a detected budget of %d", snap.MemoryLimit, snap.MemoryBudget)
	}
	if snap.MemoryLimit >= int64(snap.MemoryBudget) {
		t.Errorf("MemoryLimit %d >= budget %d: no headroom left for stacks and runtime metadata",
			snap.MemoryLimit, snap.MemoryBudget)
	}
	if applied := debug.SetMemoryLimit(-1); applied != snap.MemoryLimit {
		t.Errorf("runtime memory limit = %d, Snapshot says %d", applied, snap.MemoryLimit)
	}

	mu.Lock()
	n := len(logs)
	mu.Unlock()
	if n == 0 {
		t.Error("Logf was never called; startup state would be invisible in production")
	}
}

func TestStartRespectsEnvPins(t *testing.T) {
	restoreGC(t)
	t.Setenv("GOGC", "77")
	t.Setenv("GOMEMLIMIT", "3GiB")

	// The process already parsed GOGC at startup, so setting it here does not
	// change the live value. What matters is that the tuner declines to override
	// a knob the operator pinned.
	before := currentGOGC()
	beforeLimit := debug.SetMemoryLimit(-1)

	cfg := DefaultConfig()
	cfg.RespectEnv = true
	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tn.Stop()

	if after := currentGOGC(); after != before {
		t.Errorf("GOGC changed from %d to %d despite GOGC being pinned in the environment", before, after)
	}
	if after := debug.SetMemoryLimit(-1); after != beforeLimit {
		t.Errorf("memory limit changed from %d to %d despite GOMEMLIMIT being pinned", beforeLimit, after)
	}
	snap := tn.Snapshot()
	if !snap.GOGCPinnedByEnv {
		t.Error("Snapshot.GOGCPinnedByEnv = false with GOGC set")
	}
	if !snap.MemLimitPinnedByEnv {
		t.Error("Snapshot.MemLimitPinnedByEnv = false with GOMEMLIMIT set")
	}
}

func TestTickDoesNotAdjustPinnedGOGC(t *testing.T) {
	restoreGC(t)
	t.Setenv("GOGC", "123")

	cfg := DefaultConfig()
	cfg.Interval = time.Second
	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tn.Stop()

	before := currentGOGC()
	tn.tick() // baseline
	tn.tick() // would adjust if not pinned
	if after := currentGOGC(); after != before {
		t.Errorf("tick changed pinned GOGC from %d to %d", before, after)
	}
	if got := tn.Snapshot().LastAdjustReason; got != "gogc-pinned-by-env" {
		t.Errorf("LastAdjustReason = %q, want gogc-pinned-by-env", got)
	}
}

func TestTickUpdatesObservabilityFields(t *testing.T) {
	restoreGC(t)

	cfg := DefaultConfig()
	cfg.RespectEnv = false
	cfg.Interval = time.Second
	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tn.Stop()

	tn.tick()
	if got := tn.Snapshot().LastAdjustReason; got != "baseline-sample" {
		t.Errorf("after first tick LastAdjustReason = %q, want baseline-sample", got)
	}

	// Generate real garbage so the second tick has a nonzero CPU delta to divide.
	for i := 0; i < 200; i++ {
		_ = make([]byte, 64<<10)
	}
	runtime.GC()
	tn.tick()

	snap := tn.Snapshot()
	if snap.LastAdjustReason == "baseline-sample" {
		t.Error("second tick still reports baseline-sample")
	}
	if snap.LastGCCPUFraction < 0 || snap.LastGCCPUFraction > 1 {
		t.Errorf("LastGCCPUFraction = %v, want within [0,1]", snap.LastGCCPUFraction)
	}
	if snap.LastHeapPressure < 0 {
		t.Errorf("LastHeapPressure = %v, want >= 0", snap.LastHeapPressure)
	}
}

func TestStopIsIdempotentAndConcurrencySafe(t *testing.T) {
	restoreGC(t)

	cfg := DefaultConfig()
	cfg.RespectEnv = false
	cfg.Interval = time.Second
	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tn.Stop()
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent Stop deadlocked")
	}
}

func TestSnapshotIsRaceFreeUnderConcurrentTicks(t *testing.T) {
	restoreGC(t)

	cfg := DefaultConfig()
	cfg.RespectEnv = false
	cfg.Interval = time.Second
	tn, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer tn.Stop()

	// Exercised under -race: readers and the controller share Tuner.state.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = tn.Snapshot()
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		tn.tick()
	}
	close(stop)
	wg.Wait()
}

func TestDetectMemoryBudgetIsPlausible(t *testing.T) {
	budget, source := DetectMemoryBudget()
	if source == "" {
		t.Error("DetectMemoryBudget returned an empty source string")
	}
	t.Logf("detected budget=%s source=%s on %s/%s", humanBytes(budget), source, runtime.GOOS, runtime.GOARCH)

	switch runtime.GOOS {
	case "linux", "windows", "darwin", "freebsd", "netbsd", "openbsd", "dragonfly":
		if budget == 0 {
			t.Errorf("budget = 0 (source=%q) on a supported platform", source)
		}
		// 64MiB floor rules out a misparse yielding a tiny number; 16TiB ceiling
		// rules out reading a sentinel as a real limit.
		if budget != 0 && (budget < 64<<20 || budget > 16<<40) {
			t.Errorf("budget %s (source=%q) is implausible", humanBytes(budget), source)
		}
	default:
		if budget != 0 {
			t.Errorf("budget = %d on an unsupported platform, want 0", budget)
		}
		if source != "unsupported-platform" {
			t.Errorf("source = %q, want unsupported-platform", source)
		}
	}
}

func TestDetectMemoryBudgetIsStable(t *testing.T) {
	// Detection reads immutable-per-boot facts; a varying answer means a parse
	// depending on transient state, which would make the applied limit unstable
	// across restarts.
	first, firstSrc := DetectMemoryBudget()
	for i := 0; i < 5; i++ {
		got, src := DetectMemoryBudget()
		if got != first || src != firstSrc {
			t.Fatalf("detection unstable: (%d,%q) then (%d,%q)", first, firstSrc, got, src)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "unknown"},
		{512, "512B"},
		{1024, "1KiB"},
		{1536, "1.5KiB"},
		{1 << 20, "1MiB"},
		{1 << 30, "1GiB"},
		{3 << 30, "3GiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.in); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanBytesSigned(t *testing.T) {
	if got := humanBytesSigned(0); got != "unset" {
		t.Errorf("humanBytesSigned(0) = %q, want unset", got)
	}
	if got := humanBytesSigned(-1); got != "unset" {
		t.Errorf("humanBytesSigned(-1) = %q, want unset", got)
	}
	if got := humanBytesSigned(math.MaxInt64); got != "unlimited" {
		t.Errorf("humanBytesSigned(MaxInt64) = %q, want unlimited", got)
	}
	if got := humanBytesSigned(1 << 30); got != "1GiB" {
		t.Errorf("humanBytesSigned(1GiB) = %q, want 1GiB", got)
	}
}

func BenchmarkDetectMemoryBudget(b *testing.B) {
	// Called once per process, but a pathological cost here would show up as
	// startup latency, so it is worth knowing.
	for b.Loop() {
		_, _ = DetectMemoryBudget()
	}
}

func BenchmarkTunerTick(b *testing.B) {
	tn := &Tuner{cfg: DefaultConfig()}
	tn.initSamples()
	tn.state.InitialGOGC = 100
	tn.state.GOGC = 100
	for b.Loop() {
		tn.tick()
	}
}

func BenchmarkDecide(b *testing.B) {
	tn := &Tuner{cfg: DefaultConfig()}
	tn.state.InitialGOGC = 100
	for b.Loop() {
		_, _ = tn.decide(150, 0.08, true, 0.30)
	}
}
