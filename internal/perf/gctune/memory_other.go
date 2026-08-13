//go:build !linux && !windows && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package gctune

// DetectMemoryBudget reports the memory this process may actually use, and how
// that figure was obtained.
//
// No detection mechanism is implemented for this platform, so it reports failure
// and the tuner leaves the memory limit to the operator. This is the correct
// outcome: a fabricated budget would be worse than no limit, because GOMEMLIMIT
// set too low causes continuous GC thrash and set too high causes the OOM kill it
// was meant to prevent.
func DetectMemoryBudget() (uint64, string) {
	return 0, "unsupported-platform"
}
