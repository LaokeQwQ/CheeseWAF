package cli

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/perf/gctune"
)

func TestGCTuneConfigZeroFieldsFallBackToTunerDefaults(t *testing.T) {
	// A config file that only sets `enabled` must still produce a fully
	// populated profile, otherwise the tuner would receive zeros and reject them.
	got := gcTuneConfigFromConfig(config.GCTuningConfig{Enabled: true})
	def := gctune.DefaultConfig()

	if !got.Enabled {
		t.Error("Enabled = false, want true")
	}
	if got.MemoryLimitRatio != def.MemoryLimitRatio {
		t.Errorf("MemoryLimitRatio = %v, want default %v", got.MemoryLimitRatio, def.MemoryLimitRatio)
	}
	if got.MinGOGC != def.MinGOGC || got.MaxGOGC != def.MaxGOGC {
		t.Errorf("GOGC clamps = [%d,%d], want defaults [%d,%d]", got.MinGOGC, got.MaxGOGC, def.MinGOGC, def.MaxGOGC)
	}
	if got.TargetGCCPUFraction != def.TargetGCCPUFraction {
		t.Errorf("TargetGCCPUFraction = %v, want default %v", got.TargetGCCPUFraction, def.TargetGCCPUFraction)
	}
	if got.Interval != def.Interval {
		t.Errorf("Interval = %v, want default %v", got.Interval, def.Interval)
	}
	if got.Logf == nil {
		t.Error("Logf is nil; adjustments would be invisible to operators")
	}
}

func TestGCTuneConfigAppliesExplicitOverrides(t *testing.T) {
	in := config.GCTuningConfig{
		Enabled:             true,
		MemoryLimitRatio:    0.5,
		MinGOGC:             80,
		MaxGOGC:             300,
		BaseGOGC:            120,
		TargetGCCPUFraction: 0.02,
		Interval:            90 * time.Second,
	}
	got := gcTuneConfigFromConfig(in)

	if got.MemoryLimitRatio != 0.5 {
		t.Errorf("MemoryLimitRatio = %v, want 0.5", got.MemoryLimitRatio)
	}
	if got.MinGOGC != 80 || got.MaxGOGC != 300 {
		t.Errorf("GOGC clamps = [%d,%d], want [80,300]", got.MinGOGC, got.MaxGOGC)
	}
	if got.BaseGOGC != 120 {
		t.Errorf("BaseGOGC = %d, want 120", got.BaseGOGC)
	}
	if got.TargetGCCPUFraction != 0.02 {
		t.Errorf("TargetGCCPUFraction = %v, want 0.02", got.TargetGCCPUFraction)
	}
	if got.Interval != 90*time.Second {
		t.Errorf("Interval = %v, want 90s", got.Interval)
	}
}

func TestGCTuneConfigDisabledPropagates(t *testing.T) {
	got := gcTuneConfigFromConfig(config.GCTuningConfig{Enabled: false})
	if got.Enabled {
		t.Error("Enabled = true, want false")
	}
}

func TestDefaultConfigEnablesGCTuning(t *testing.T) {
	// The whole point is that operators get the tuning without opting in.
	if !config.Default().Performance.GC.Enabled {
		t.Error("config.Default() ships with GC tuning disabled")
	}
}

func TestMappedDefaultConfigIsAcceptedByTuner(t *testing.T) {
	// Guards the seam between the two packages: a default that the tuner would
	// reject at validate() time would silently disable tuning in production.
	mapped := gcTuneConfigFromConfig(config.Default().Performance.GC)
	tuner, err := gctune.Start(mapped)
	if err != nil {
		t.Fatalf("tuner rejected the mapped default config: %v", err)
	}
	defer tuner.Stop()
	if snap := tuner.Snapshot(); !snap.Enabled {
		t.Error("tuner reports disabled after starting with the mapped default config")
	}
}
