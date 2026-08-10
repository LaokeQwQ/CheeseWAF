//go:build freebsd || netbsd || openbsd || dragonfly

package gctune

import "golang.org/x/sys/unix"

// DetectMemoryBudget reports the memory this process may actually use, and how
// that figure was obtained.
//
// The BSDs expose physical memory through hw.physmem (bytes). Some report a
// signed value, hence the uint64 read followed by a sanity check rather than
// trusting the raw result.
//
// A returned budget of 0 means detection failed; callers must treat that as
// "leave the runtime alone" rather than substituting a guess.
func DetectMemoryBudget() (uint64, string) {
	for _, name := range []string{"hw.physmem", "hw.physmem64", "hw.usermem"} {
		v, err := unix.SysctlUint64(name)
		if err == nil && v > 0 && v < 1<<60 {
			return v, "sysctl-" + name
		}
	}
	return 0, "undetected"
}
