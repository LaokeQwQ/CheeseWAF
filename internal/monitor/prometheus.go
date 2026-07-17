// Package monitor exposes metrics, alerting, and remote write helpers.
package monitor

import (
	"bytes"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine/semantic"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Snapshot struct {
	GeneratedAt   time.Time        `json:"generated_at"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	Goroutines    int              `json:"goroutines"`
	ProcessCount  int              `json:"process_count"`
	MemoryAlloc   uint64           `json:"memory_alloc"`
	Host          HostStats        `json:"host"`
	Sites         int              `json:"sites"`
	Requests      int              `json:"requests"`
	Blocked       int              `json:"blocked"`
	Challenges    int              `json:"challenges"`
	StatusCodes   map[int]int      `json:"status_codes"`
	Categories    map[string]int   `json:"categories"`
	DiskUsage     map[string]int64 `json:"disk_usage"`
}

func Collect(startedAt time.Time, sites int, logs []storage.LogEntry, diskUsage map[string]int64) Snapshot {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	snapshot := Snapshot{
		GeneratedAt:   time.Now().UTC(),
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		Goroutines:    runtime.NumGoroutine(),
		ProcessCount:  CollectProcessCount(),
		MemoryAlloc:   mem.Alloc,
		Host:          CollectHostStats(),
		Sites:         sites,
		StatusCodes:   map[int]int{},
		Categories:    map[string]int{},
		DiskUsage:     diskUsage,
	}
	for _, entry := range logs {
		snapshot.Requests++
		if entry.Action == "block" {
			snapshot.Blocked++
		}
		if entry.Action == "challenge" {
			snapshot.Challenges++
		}
		if entry.StatusCode != 0 {
			snapshot.StatusCodes[entry.StatusCode]++
		}
		if entry.Category != "" {
			snapshot.Categories[entry.Category]++
		}
	}
	return snapshot
}

func RenderPrometheus(snapshot Snapshot) []byte {
	var buf bytes.Buffer
	writeMetric(&buf, "cheesewaf_uptime_seconds", "CheeseWAF process uptime in seconds.", float64(snapshot.UptimeSeconds), nil)
	writeMetric(&buf, "cheesewaf_goroutines", "Current goroutine count.", float64(snapshot.Goroutines), nil)
	writeMetric(&buf, "cheesewaf_process_count", "CheeseWAF service process count.", float64(snapshot.ProcessCount), nil)
	writeMetric(&buf, "cheesewaf_memory_alloc_bytes", "Current allocated heap bytes.", float64(snapshot.MemoryAlloc), nil)
	writeMetric(&buf, "cheesewaf_host_cpu_percent", "Host CPU usage percent.", snapshot.Host.CPUPercent, nil)
	writeMetric(&buf, "cheesewaf_host_memory_percent", "Host memory usage percent.", snapshot.Host.MemoryPercent, nil)
	writeMetric(&buf, "cheesewaf_host_disk_percent", "Host root disk usage percent.", snapshot.Host.DiskPercent, nil)
	writeMetric(&buf, "cheesewaf_sites", "Configured sites.", float64(snapshot.Sites), nil)
	writeMetric(&buf, "cheesewaf_requests_total", "Observed access log events.", float64(snapshot.Requests), nil)
	writeMetric(&buf, "cheesewaf_blocked_total", "Blocked access log events.", float64(snapshot.Blocked), nil)
	writeMetric(&buf, "cheesewaf_challenges_total", "Challenge access log events.", float64(snapshot.Challenges), nil)
	for _, code := range sortedIntKeys(snapshot.StatusCodes) {
		writeMetric(&buf, "cheesewaf_status_total", "Events by status code.", float64(snapshot.StatusCodes[code]), map[string]string{"code": fmt.Sprint(code)})
	}
	for _, category := range sortedStringKeys(snapshot.Categories) {
		writeMetric(&buf, "cheesewaf_attack_category_total", "Events by WAF category.", float64(snapshot.Categories[category]), map[string]string{"category": category})
	}
	for _, name := range sortedStringKeys(snapshot.DiskUsage) {
		writeMetric(&buf, "cheesewaf_disk_usage_bytes", "Disk usage by area.", float64(snapshot.DiskUsage[name]), map[string]string{"area": name})
	}
	// Semantic analyzer process counters (complements per-event detector_id/confidence in logs).
	sem := semantic.ProcessMetrics().Snapshot()
	writeMetric(&buf, "cheesewaf_semantic_analyzed_total", "Semantic analyzer requests analyzed.", float64(sem.Analyzed), nil)
	writeMetric(&buf, "cheesewaf_semantic_passed_total", "Semantic analyzer clean passes.", float64(sem.Passed), nil)
	writeMetric(&buf, "cheesewaf_semantic_hit_total", "Semantic analyzer detections (any action).", float64(sem.Hit), nil)
	writeMetric(&buf, "cheesewaf_semantic_blocked_total", "Semantic analyzer block-mode detections.", float64(sem.Blocked), nil)
	writeMetric(&buf, "cheesewaf_semantic_budget_exhausted_total", "Detection budget exhausted events.", float64(sem.BudgetExhausted), nil)
	writeMetric(&buf, "cheesewaf_semantic_avg_latency_ns", "Average semantic analyzer latency in nanoseconds.", float64(sem.AvgLatencyNs), nil)
	for _, bucket := range sortedStringKeys(sem.LatencyBuckets) {
		writeMetric(&buf, "cheesewaf_semantic_latency_bucket_total", "Semantic latency histogram buckets.", float64(sem.LatencyBuckets[bucket]), map[string]string{"bucket": bucket})
	}
	for _, category := range sortedStringKeys(sem.HitByCategory) {
		writeMetric(&buf, "cheesewaf_semantic_hit_by_category_total", "Semantic hits by category.", float64(sem.HitByCategory[category]), map[string]string{"category": category})
	}
	for _, category := range sortedStringKeys(sem.BlockByCategory) {
		writeMetric(&buf, "cheesewaf_semantic_block_by_category_total", "Semantic blocks by category.", float64(sem.BlockByCategory[category]), map[string]string{"category": category})
	}
	writeMetric(&buf, "cheesewaf_semantic_cache_hits_total", "Semantic candidate cache hits.", float64(sem.CacheHits), nil)
	writeMetric(&buf, "cheesewaf_semantic_cache_misses_total", "Semantic candidate cache misses.", float64(sem.CacheMisses), nil)
	writeMetric(&buf, "cheesewaf_semantic_allowlist_path_skips_total", "Semantic path allowlist skip events.", float64(sem.AllowlistPathSkips), nil)
	writeMetric(&buf, "cheesewaf_semantic_allowlist_param_skips_total", "Semantic param allowlist skip events.", float64(sem.AllowlistParamSkips), nil)
	return buf.Bytes()
}

func Values(snapshot Snapshot) map[string]float64 {
	values := map[string]float64{
		"cheesewaf_uptime_seconds":      float64(snapshot.UptimeSeconds),
		"cheesewaf_goroutines":          float64(snapshot.Goroutines),
		"cheesewaf_process_count":       float64(snapshot.ProcessCount),
		"cheesewaf_memory_alloc_bytes":  float64(snapshot.MemoryAlloc),
		"cheesewaf_host_cpu_percent":    snapshot.Host.CPUPercent,
		"cheesewaf_host_memory_percent": snapshot.Host.MemoryPercent,
		"cheesewaf_host_disk_percent":   snapshot.Host.DiskPercent,
		"cheesewaf_sites":               float64(snapshot.Sites),
		"cheesewaf_requests_total":      float64(snapshot.Requests),
		"cheesewaf_blocked_total":       float64(snapshot.Blocked),
		"cheesewaf_challenges_total":    float64(snapshot.Challenges),
	}
	for area, usage := range snapshot.DiskUsage {
		values["cheesewaf_disk_usage_bytes:"+area] = float64(usage)
	}
	return values
}

func writeMetric(buf *bytes.Buffer, name, help string, value float64, labels map[string]string) {
	fmt.Fprintf(buf, "# HELP %s %s\n", name, help)
	fmt.Fprintf(buf, "# TYPE %s gauge\n", name)
	if len(labels) == 0 {
		fmt.Fprintf(buf, "%s %g\n", name, value)
		return
	}
	fmt.Fprintf(buf, "%s{%s} %g\n", name, renderLabels(labels), value)
}

func renderLabels(labels map[string]string) string {
	keys := sortedStringKeys(labels)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := strings.ReplaceAll(labels[key], `"`, `\"`)
		parts = append(parts, fmt.Sprintf(`%s="%s"`, key, value))
	}
	return strings.Join(parts, ",")
}

func sortedIntKeys(values map[int]int) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func sortedStringKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
