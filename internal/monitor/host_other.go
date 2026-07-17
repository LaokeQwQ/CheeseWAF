//go:build !linux && !windows

package monitor

import (
	"runtime"
	"time"
)

// CollectHostStats returns a minimal snapshot on platforms without a dedicated collector.
func CollectHostStats() HostStats {
	return HostStats{OS: runtime.GOOS, CPUCount: runtime.NumCPU(), SampledAt: time.Now().UTC()}
}
