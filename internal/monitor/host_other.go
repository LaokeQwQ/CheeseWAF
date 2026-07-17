//go:build !linux

package monitor

import (
	"runtime"
	"time"
)

type HostStats struct {
	OS            string    `json:"os"`
	CPUCount      int       `json:"cpu_count"`
	CPUPercent    float64   `json:"cpu_percent"`
	Load1         float64   `json:"load1"`
	MemoryTotal   uint64    `json:"memory_total"`
	MemoryUsed    uint64    `json:"memory_used"`
	MemoryPercent float64   `json:"memory_percent"`
	SwapTotal     uint64    `json:"swap_total"`
	SwapUsed      uint64    `json:"swap_used"`
	SwapPercent   float64   `json:"swap_percent"`
	DiskTotal     uint64    `json:"disk_total"`
	DiskUsed      uint64    `json:"disk_used"`
	DiskPercent   float64   `json:"disk_percent"`
	SampledAt     time.Time `json:"sampled_at"`
}

func CollectHostStats() HostStats {
	return HostStats{OS: runtime.GOOS, CPUCount: runtime.NumCPU(), SampledAt: time.Now().UTC()}
}
