package setup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HardwareProfile is the Setup 2.0 recommended performance tier.
type HardwareProfile string

const (
	ProfileLow    HardwareProfile = "low"
	ProfileMedium HardwareProfile = "medium"
	ProfileSmart  HardwareProfile = "smart"
	ProfileHigh   HardwareProfile = "high"
	ProfileCustom HardwareProfile = "custom"
)

// ProbeResult is the outcome of a bounded first-install performance probe.
type ProbeResult struct {
	Profile         HardwareProfile `json:"profile"`
	Incomplete      bool            `json:"incomplete"`
	CPULogical      int             `json:"cpu_logical"`
	MemoryTotalMB   uint64          `json:"memory_total_mb"`
	MemoryAvailMB   uint64          `json:"memory_avail_mb"`
	DiskWriteMBps   float64         `json:"disk_write_mbps"`
	DiskOK          bool            `json:"disk_ok"`
	DurationMS      int64           `json:"duration_ms"`
	Notes           []string        `json:"notes,omitempty"`
	SuggestedConfig ProfileConfig   `json:"suggested_config"`
}

// ProfileConfig maps a tier to safe defaults (Setup custom knobs minimum set).
type ProfileConfig struct {
	PipelineBudgetMS     int    `json:"pipeline_budget_ms"`
	SemanticDepth        int    `json:"semantic_depth"`
	WebAttackLevel       string `json:"web_attack_level"`
	ChallengeConcurrency int    `json:"challenge_concurrency"`
	ChallengeCapacity    int    `json:"challenge_capacity"`
	RateLimitRequests    int    `json:"rate_limit_requests"`
	MaxBodyBytes         int64  `json:"max_body_bytes"`
	AccessLogSamplePct   int    `json:"access_log_sample_pct"`
}

// ProfileDefaults returns the locked mapping for low/medium/high.
func ProfileDefaults(p HardwareProfile) ProfileConfig {
	switch p {
	case ProfileHigh:
		return ProfileConfig{
			PipelineBudgetMS: 80, SemanticDepth: 3, WebAttackLevel: "high",
			ChallengeConcurrency: 128, ChallengeCapacity: 20000,
			RateLimitRequests: 200, MaxBodyBytes: 16 << 20, AccessLogSamplePct: 100,
		}
	case ProfileMedium:
		return ProfileConfig{
			PipelineBudgetMS: 50, SemanticDepth: 2, WebAttackLevel: "smart",
			ChallengeConcurrency: 64, ChallengeCapacity: 10000,
			RateLimitRequests: 100, MaxBodyBytes: 8 << 20, AccessLogSamplePct: 100,
		}
	case ProfileSmart:
		// Smart adaptive: smart scoring at the lowest overhead. Sits between low
		// and medium on resources because it relies on scoring rather than depth.
		return ProfileConfig{
			PipelineBudgetMS: 40, SemanticDepth: 2, WebAttackLevel: "smart",
			ChallengeConcurrency: 48, ChallengeCapacity: 7500,
			RateLimitRequests: 80, MaxBodyBytes: 6 << 20, AccessLogSamplePct: 100,
		}
	default: // low / incomplete
		return ProfileConfig{
			PipelineBudgetMS: 30, SemanticDepth: 1, WebAttackLevel: "smart",
			ChallengeConcurrency: 32, ChallengeCapacity: 5000,
			RateLimitRequests: 50, MaxBodyBytes: 4 << 20, AccessLogSamplePct: 50,
		}
	}
}

// RunProbe executes a bounded probe (≤30s). Failures/timeouts yield low + Incomplete.
func RunProbe(ctx context.Context, dataDir string) ProbeResult {
	start := time.Now()
	deadline := 30 * time.Second
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), deadline)
		defer cancel()
	}
	res := ProbeResult{
		CPULogical: runtime.NumCPU(),
		Notes:      []string{},
	}
	// Memory is read from the host where the platform exposes it. The fallback
	// remains conservative and is covered by the incomplete-probe path.
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	res.MemoryTotalMB, res.MemoryAvailMB = estimateHostMemory()
	if res.MemoryAvailMB == 0 {
		res.MemoryAvailMB = 512
	}

	// Disk sequential write sample under dataDir.
	diskCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	mbps, diskOK, diskNote := probeDiskWrite(diskCtx, dataDir)
	res.DiskWriteMBps = mbps
	res.DiskOK = diskOK
	if diskNote != "" {
		res.Notes = append(res.Notes, diskNote)
	}

	select {
	case <-ctx.Done():
		res.Incomplete = true
		res.Notes = append(res.Notes, "probe cancelled or timed out")
		res.Profile = ProfileLow
	default:
		res.Profile = classifyHardware(res)
	}
	if res.Incomplete {
		res.Profile = ProfileLow
	}
	res.SuggestedConfig = ProfileDefaults(res.Profile)
	res.DurationMS = time.Since(start).Milliseconds()
	return res
}

func classifyHardware(r ProbeResult) HardwareProfile {
	// Barrel principle (locked): low ≤2 logical cores OR RAM≤2G OR weak disk;
	// medium ≥3C and RAM≥4G; high ≥4C and RAM≥8G and disk sequential write OK.
	if r.CPULogical <= 2 || r.MemoryTotalMB <= 2048 || !r.DiskOK {
		return ProfileLow
	}
	if r.CPULogical >= 4 && r.MemoryTotalMB >= 8192 && r.DiskOK && r.DiskWriteMBps >= 50 {
		return ProfileHigh
	}
	if r.CPULogical >= 3 && r.MemoryTotalMB >= 4096 {
		return ProfileMedium
	}
	return ProfileLow
}

func estimateHostMemoryMB() uint64 {
	total, _ := estimateHostMemory()
	return total
}

func estimateHostMemory() (totalMB, availableMB uint64) {
	if v := os.Getenv("CHEESEWAF_PROBE_MEMORY_MB"); v != "" {
		var n uint64
		_, _ = fmt.Sscanf(v, "%d", &n)
		if n > 0 {
			return n, n / 2
		}
	}

	// Linux exposes host-visible totals through procfs. Prefer a cgroup limit
	// when one is smaller, so a constrained container is not treated as a full
	// host.
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		var procTotal, procAvailable uint64
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "MemTotal:" {
				if len(fields) >= 2 && fields[0] == "MemAvailable:" {
					if kib, parseErr := strconv.ParseUint(fields[1], 10, 64); parseErr == nil {
						procAvailable = kib / 1024
					}
				}
				continue
			}
			kib, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil && kib > 0 {
				procTotal = kib / 1024
			}
		}
		if procTotal > 0 {
			totalMB = procTotal
			availableMB = procAvailable
		}
	}

	if limitMB := readCgroupMemoryLimitMB(); limitMB > 0 && (totalMB == 0 || limitMB < totalMB) {
		totalMB = limitMB
		if availableMB > totalMB {
			availableMB = totalMB / 2
		}
	}
	if totalMB > 0 {
		if availableMB == 0 {
			availableMB = totalMB / 2
		}
		return totalMB, availableMB
	}

	// Other platforms keep the previous conservative floor until a native
	// memory provider is available.
	return 4096, 2048
}

func readCgroupMemoryLimitMB() uint64 {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(raw))
		if value == "" || value == "max" {
			continue
		}
		bytes, err := strconv.ParseUint(value, 10, 64)
		if err != nil || bytes == 0 || bytes >= 1<<60 {
			continue
		}
		return (bytes + (1 << 20) - 1) / (1 << 20)
	}
	return 0
}

func probeDiskWrite(ctx context.Context, dataDir string) (mbps float64, ok bool, note string) {
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	dir := filepath.Join(dataDir, ".probe")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, false, "disk probe: cannot create temp dir"
	}
	path := filepath.Join(dir, fmt.Sprintf("write-%d.bin", time.Now().UnixNano()))
	defer func() { _ = os.Remove(path); _ = os.Remove(dir) }()

	const size = 8 << 20 // 8 MiB
	buf := make([]byte, 64<<10)
	for i := range buf {
		buf[i] = byte(i)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, false, "disk probe: open failed"
	}
	start := time.Now()
	written := 0
	for written < size {
		select {
		case <-ctx.Done():
			_ = f.Close()
			return 0, false, "disk probe: timed out"
		default:
		}
		n, werr := f.Write(buf)
		written += n
		if werr != nil {
			_ = f.Close()
			return 0, false, "disk probe: write failed"
		}
	}
	_ = f.Sync()
	_ = f.Close()
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	mbps = (float64(written) / (1024 * 1024)) / elapsed
	// Weak disk: below ~20 MB/s sequential treated as not OK for medium/high.
	return mbps, mbps >= 20, ""
}
