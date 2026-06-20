//go:build linux

package monitor

import (
	"os"
	"path/filepath"
	"strconv"
)

func CollectProcessCount() int {
	executable, err := os.Executable()
	if err != nil {
		return 1
	}
	executable, _ = filepath.EvalSymlinks(executable)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 1
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		target, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		target, _ = filepath.EvalSymlinks(target)
		if target == executable {
			count++
		}
	}
	if count == 0 {
		return 1
	}
	return count
}
