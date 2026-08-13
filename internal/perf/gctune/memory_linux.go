//go:build linux

package gctune

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
)

// DetectMemoryBudget reports the memory this process may actually use, and how
// that figure was obtained.
//
// Order matters. A container's cgroup limit is the real ceiling even when the
// host has far more RAM, and reading /proc/meminfo inside a container reports
// the host's memory — the classic reason Go services get OOM-killed at a
// fraction of what they think is available. So cgroup limits are consulted
// first, and only an absent or effectively-unlimited limit falls through to
// physical memory.
//
// A returned budget of 0 means detection failed; callers must treat that as
// "leave the runtime alone" rather than substituting a guess.
func DetectMemoryBudget() (uint64, string) {
	if v, src, ok := cgroupMemoryLimit(); ok {
		// A cgroup limit larger than physical RAM is not a real constraint; the
		// host's memory is the binding one.
		if phys, physSrc, physOK := physicalMemory(); physOK && v >= phys {
			return phys, physSrc + "+cgroup-unbounded"
		}
		return v, src
	}
	if v, src, ok := physicalMemory(); ok {
		return v, src
	}
	return 0, "undetected"
}

// cgroupMemoryLimit reads the memory ceiling from cgroup v2 then v1.
//
// v2 exposes memory.max containing either a byte count or the literal "max".
// v1 exposes memory.limit_in_bytes, which when unlimited holds a sentinel near
// 2^63-1 (or 2^64-1 page-aligned depending on kernel), so any implausibly large
// value is treated as absent.
func cgroupMemoryLimit() (uint64, string, bool) {
	// cgroup v2 unified hierarchy, standard mount point.
	if v, ok := readCgroupV2Limit("/sys/fs/cgroup/memory.max"); ok {
		return v, "cgroup-v2", true
	}
	// Delegated/nested v2 path recorded in /proc/self/cgroup as "0::<path>".
	if rel, ok := cgroupV2RelativePath(); ok && rel != "/" {
		if v, ok := readCgroupV2Limit("/sys/fs/cgroup" + rel + "/memory.max"); ok {
			return v, "cgroup-v2-nested", true
		}
	}
	// cgroup v1.
	for _, p := range []string{
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes.effective",
	} {
		if v, ok := readCgroupV1Limit(p); ok {
			return v, "cgroup-v1", true
		}
	}
	return 0, "", false
}

func readCgroupV2Limit(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

func readCgroupV1Limit(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	// Unlimited sentinels: kernels report values at or near the 64-bit maximum,
	// sometimes rounded down to a page boundary. Anything above an exabyte is
	// not a real container limit.
	if v >= uint64(math.MaxInt64) || v > 1<<60 {
		return 0, false
	}
	return v, true
}

func cgroupV2RelativePath() (string, bool) {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// v2 entries have an empty controller list: "0::<path>".
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// physicalMemory reads MemTotal from /proc/meminfo, which is reported in
// kibibytes.
func physicalMemory() (uint64, string, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "MemTotal:" {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, "", false
		}
		return kb * 1024, "proc-meminfo", true
	}
	return 0, "", false
}
