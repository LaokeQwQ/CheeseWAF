//go:build !linux

package monitor

func CollectProcessCount() int {
	return 1
}
