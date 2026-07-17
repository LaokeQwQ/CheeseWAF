//go:build windows

package monitor

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MEMORYSTATUSEX — kernel32 GlobalMemoryStatusEx.
// Physical RAM = ullTotalPhys / ullAvailPhys.
// Virtual memory (commit limit / pagefile-backed) = ullTotalPageFile / ullAvailPageFile.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
)

var winCPUSample struct {
	mu     sync.Mutex
	idle   uint64
	kernel uint64
	user   uint64
}

func CollectHostStats() HostStats {
	memTotal, memUsed, swapTotal, swapUsed := readWindowsMemory()
	diskTotal, diskUsed := readWorkingDirDisk()
	stats := HostStats{
		OS:          "windows",
		CPUCount:    runtime.NumCPU(),
		CPUPercent:  readWindowsCPUPercent(),
		MemoryTotal: memTotal,
		MemoryUsed:  memUsed,
		SwapTotal:   swapTotal,
		SwapUsed:    swapUsed,
		DiskTotal:   diskTotal,
		DiskUsed:    diskUsed,
		SampledAt:   time.Now().UTC(),
	}
	stats.MemoryPercent = percent(float64(stats.MemoryUsed), float64(stats.MemoryTotal))
	stats.SwapPercent = percent(float64(stats.SwapUsed), float64(stats.SwapTotal))
	stats.DiskPercent = percent(float64(stats.DiskUsed), float64(stats.DiskTotal))
	return stats
}

func readWindowsMemory() (memTotal, memUsed, swapTotal, swapUsed uint64) {
	var status memoryStatusEx
	status.Length = uint32(unsafe.Sizeof(status))
	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if r1 == 0 {
		return 0, 0, 0, 0
	}
	memTotal = status.TotalPhys
	memUsed = saturatingSub(status.TotalPhys, status.AvailPhys)
	// Windows "virtual memory" / pagefile-backed commit limit.
	swapTotal = status.TotalPageFile
	swapUsed = saturatingSub(status.TotalPageFile, status.AvailPageFile)
	return memTotal, memUsed, swapTotal, swapUsed
}

// Disk usage of the volume that holds the process working directory.
func readWorkingDirDisk() (total, used uint64) {
	path := workingDirPath()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0
	}
	var freeToCaller, totalBytes, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(ptr, &freeToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0
	}
	return totalBytes, saturatingSub(totalBytes, totalFree)
}

func workingDirPath() string {
	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Dir(exe)
	}
	return `.`
}

func readWindowsCPUPercent() float64 {
	var idle, kernel, user windows.Filetime
	r1, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idle)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if r1 == 0 {
		return 0
	}
	idleTicks := filetimeToUint64(idle)
	kernelTicks := filetimeToUint64(kernel)
	userTicks := filetimeToUint64(user)

	winCPUSample.mu.Lock()
	defer winCPUSample.mu.Unlock()
	prevIdle, prevKernel, prevUser := winCPUSample.idle, winCPUSample.kernel, winCPUSample.user
	winCPUSample.idle, winCPUSample.kernel, winCPUSample.user = idleTicks, kernelTicks, userTicks
	if prevKernel == 0 && prevUser == 0 {
		return 0
	}
	// Kernel time includes idle time on Windows.
	deltaIdle := saturatingSub(idleTicks, prevIdle)
	deltaKernel := saturatingSub(kernelTicks, prevKernel)
	deltaUser := saturatingSub(userTicks, prevUser)
	deltaTotal := deltaKernel + deltaUser
	if deltaTotal == 0 || deltaIdle > deltaTotal {
		return 0
	}
	return percent(float64(deltaTotal-deltaIdle), float64(deltaTotal))
}

func filetimeToUint64(ft windows.Filetime) uint64 {
	return (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
}
