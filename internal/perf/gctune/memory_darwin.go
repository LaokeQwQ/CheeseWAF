//go:build darwin

package gctune

import "golang.org/x/sys/unix"

// DetectMemoryBudget reports the memory this process may actually use, and how
// that figure was obtained.
//
// macOS has no cgroup equivalent that applies to a normally-launched process, so
// physical memory from the hw.memsize sysctl is the budget. Docker Desktop on
// macOS runs containers inside a Linux VM, where the linux build of this file
// applies instead.
//
// A returned budget of 0 means detection failed; callers must treat that as
// "leave the runtime alone" rather than substituting a guess.
func DetectMemoryBudget() (uint64, string) {
	if v, err := unix.SysctlUint64("hw.memsize"); err == nil && v > 0 {
		return v, "sysctl-hw.memsize"
	}
	return 0, "undetected"
}
