//go:build linux

package monitor

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var cpuSample struct {
	mu    sync.Mutex
	total uint64
	idle  uint64
}

func CollectHostStats() HostStats {
	total, idle := readCPUCounters()
	memTotal, memAvailable, swapTotal, swapFree := readMemInfo()
	diskTotal, diskUsed := readRootDisk()
	stats := HostStats{
		OS:          "linux",
		CPUCount:    runtime.NumCPU(),
		Load1:       readLoad1(),
		MemoryTotal: memTotal,
		MemoryUsed:  saturatingSub(memTotal, memAvailable),
		SwapTotal:   swapTotal,
		SwapUsed:    saturatingSub(swapTotal, swapFree),
		DiskTotal:   diskTotal,
		DiskUsed:    diskUsed,
		SampledAt:   time.Now().UTC(),
	}
	stats.CPUPercent = cpuPercent(total, idle)
	stats.MemoryPercent = percent(float64(stats.MemoryUsed), float64(stats.MemoryTotal))
	stats.SwapPercent = percent(float64(stats.SwapUsed), float64(stats.SwapTotal))
	stats.DiskPercent = percent(float64(stats.DiskUsed), float64(stats.DiskTotal))
	return stats
}

func readCPUCounters() (uint64, uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	var values []uint64
	for _, field := range fields[1:] {
		value, _ := strconv.ParseUint(field, 10, 64)
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle
}

func cpuPercent(total, idle uint64) float64 {
	if total == 0 {
		return 0
	}
	cpuSample.mu.Lock()
	defer cpuSample.mu.Unlock()
	prevTotal, prevIdle := cpuSample.total, cpuSample.idle
	cpuSample.total, cpuSample.idle = total, idle
	if prevTotal == 0 || total <= prevTotal {
		return 0
	}
	deltaTotal := total - prevTotal
	deltaIdle := idle - prevIdle
	if deltaTotal == 0 || deltaIdle > deltaTotal {
		return 0
	}
	return percent(float64(deltaTotal-deltaIdle), float64(deltaTotal))
}

func readMemInfo() (uint64, uint64, uint64, uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, 0
	}
	var total, available, swapTotal, swapFree uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = value * 1024
		case "MemAvailable":
			available = value * 1024
		case "SwapTotal":
			swapTotal = value * 1024
		case "SwapFree":
			swapFree = value * 1024
		}
	}
	return total, available, swapTotal, swapFree
}

func readRootDisk() (uint64, uint64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, 0
	}
	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	return total, saturatingSub(total, available)
}

func readLoad1() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}
