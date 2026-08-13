package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/perf/gctune"
)

// gcTuneConfigFromConfig maps the YAML surface onto the tuner's config.
//
// Zero-valued fields fall back to the tuner's own defaults rather than to zero,
// so a config file that mentions only `performance.gc.enabled` still gets a
// fully populated, hardware-derived profile. That also keeps the YAML forward
// compatible: a field added to the tuner later needs no config change to work.
func gcTuneConfigFromConfig(cfg config.GCTuningConfig) gctune.Config {
	out := gctune.DefaultConfig()
	out.Enabled = cfg.Enabled
	if cfg.MemoryLimitRatio > 0 {
		out.MemoryLimitRatio = cfg.MemoryLimitRatio
	}
	if cfg.MinGOGC > 0 {
		out.MinGOGC = cfg.MinGOGC
	}
	if cfg.MaxGOGC > 0 {
		out.MaxGOGC = cfg.MaxGOGC
	}
	if cfg.BaseGOGC > 0 {
		out.BaseGOGC = cfg.BaseGOGC
	}
	if cfg.TargetGCCPUFraction > 0 {
		out.TargetGCCPUFraction = cfg.TargetGCCPUFraction
	}
	if cfg.Interval > 0 {
		out.Interval = cfg.Interval
	}
	// Adjustments are rare (minutes apart at most) and each one changes how the
	// process collects memory, so they belong in the operator-visible log.
	out.Logf = func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	}
	return out
}
