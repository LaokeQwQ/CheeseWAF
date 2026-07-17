//go:build windows

package monitor

import "testing"

func TestCollectHostStatsWindowsFillsMemorySwapDisk(t *testing.T) {
	// First sample may leave CPU at 0 (needs a prior baseline); memory/swap/disk should be live.
	_ = CollectHostStats()
	stats := CollectHostStats()
	if stats.OS != "windows" {
		t.Fatalf("os=%q", stats.OS)
	}
	if stats.CPUCount <= 0 {
		t.Fatalf("cpu_count=%d", stats.CPUCount)
	}
	if stats.MemoryTotal == 0 || stats.MemoryUsed == 0 {
		t.Fatalf("physical memory empty: total=%d used=%d", stats.MemoryTotal, stats.MemoryUsed)
	}
	if stats.MemoryUsed > stats.MemoryTotal {
		t.Fatalf("memory used > total: used=%d total=%d", stats.MemoryUsed, stats.MemoryTotal)
	}
	// Commit/virtual memory limit is always present on modern Windows.
	if stats.SwapTotal == 0 {
		t.Fatalf("virtual memory total is 0")
	}
	if stats.SwapUsed > stats.SwapTotal {
		t.Fatalf("swap used > total: used=%d total=%d", stats.SwapUsed, stats.SwapTotal)
	}
	if stats.DiskTotal == 0 {
		t.Fatalf("working-dir disk total is 0")
	}
	if stats.DiskUsed > stats.DiskTotal {
		t.Fatalf("disk used > total: used=%d total=%d", stats.DiskUsed, stats.DiskTotal)
	}
	if stats.MemoryPercent <= 0 || stats.MemoryPercent > 100 {
		t.Fatalf("memory_percent=%v", stats.MemoryPercent)
	}
	if stats.DiskPercent < 0 || stats.DiskPercent > 100 {
		t.Fatalf("disk_percent=%v", stats.DiskPercent)
	}
}
