package monitor

import "time"

// HostStats is the cross-platform host resource snapshot shown in the admin dashboard.
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

func percent(value, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return value / total * 100
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
