package setup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	// Memory (best-effort via runtime stats; OS-specific total left as heuristic).
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	// Sys is process-related; use a conservative synthetic total from host heuristics.
	res.MemoryTotalMB = estimateHostMemoryMB()
	res.MemoryAvailMB = res.MemoryTotalMB / 2
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
	// medium ≥2C and RAM≥4G; high ≥4C and RAM≥8G and disk sequential write OK.
	if r.CPULogical <= 2 || r.MemoryTotalMB <= 2048 || !r.DiskOK {
		return ProfileLow
	}
	if r.CPULogical >= 4 && r.MemoryTotalMB >= 8192 && r.DiskOK && r.DiskWriteMBps >= 50 {
		return ProfileHigh
	}
	if r.CPULogical >= 2 && r.MemoryTotalMB >= 4096 {
		return ProfileMedium
	}
	return ProfileLow
}

func estimateHostMemoryMB() uint64 {
	// Cross-platform floor: use a conservative default when OS APIs are not wired.
	// Operators on real hardware still get classification via CPU + disk + this floor.
	if v := os.Getenv("CHEESEWAF_PROBE_MEMORY_MB"); v != "" {
		var n uint64
		_, _ = fmt.Sscanf(v, "%d", &n)
		if n > 0 {
			return n
		}
	}
	// Assume at least 2 GiB for modern hosts; low tier still applies when CPU weak.
	return 4096
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
