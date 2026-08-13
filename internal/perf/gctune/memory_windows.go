//go:build windows

package gctune

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX structure. It is declared here
// rather than imported because golang.org/x/sys/windows does not export
// GlobalMemoryStatusEx or its parameter type.
//
// The Length field must be set to the struct size before the call; the API uses
// it for versioning and fails with ERROR_INVALID_PARAMETER when it is zero.
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
)

// DetectMemoryBudget reports the memory this process may actually use, and how
// that figure was obtained.
//
// Windows containers constrain memory through a Job Object rather than a cgroup,
// so the job limit is checked first: inside a container GlobalMemoryStatusEx
// reports the host's physical memory, which would overstate the budget the same
// way /proc/meminfo does on Linux. Physical memory is the fallback.
//
// A returned budget of 0 means detection failed; callers must treat that as
// "leave the runtime alone" rather than substituting a guess.
func DetectMemoryBudget() (uint64, string) {
	if v, ok := jobObjectMemoryLimit(); ok {
		if phys, physOK := physicalMemory(); physOK && v >= phys {
			return phys, "global-memory-status+job-unbounded"
		}
		return v, "windows-job-object"
	}
	if v, ok := physicalMemory(); ok {
		return v, "global-memory-status"
	}
	return 0, "undetected"
}

// jobObjectMemoryLimit reads the process memory ceiling from the Job Object the
// process belongs to, if any. Windows Server containers apply their memory limit
// this way.
//
// Passing a zero handle queries the current process's job. A process not in a
// job, or in a job without a memory limit, yields no limit.
func jobObjectMemoryLimit() (uint64, bool) {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	var retlen uint32
	err := windows.QueryInformationJobObject(
		0,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&retlen,
	)
	if err != nil {
		return 0, false
	}
	const (
		jobObjectLimitProcessMemory = 0x00000100
		jobObjectLimitJobMemory     = 0x00000200
	)
	flags := info.BasicLimitInformation.LimitFlags
	// Prefer the per-process cap when both are present: it is the one that
	// applies to this process rather than to all processes in the job combined.
	if flags&jobObjectLimitProcessMemory != 0 && info.ProcessMemoryLimit > 0 {
		return uint64(info.ProcessMemoryLimit), true
	}
	if flags&jobObjectLimitJobMemory != 0 && info.JobMemoryLimit > 0 {
		return uint64(info.JobMemoryLimit), true
	}
	return 0, false
}

func physicalMemory() (uint64, bool) {
	if err := procGlobalMemoryStatusEx.Find(); err != nil {
		return 0, false
	}
	var st memoryStatusEx
	st.Length = uint32(unsafe.Sizeof(st))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&st)))
	if r == 0 || st.TotalPhys == 0 {
		return 0, false
	}
	return st.TotalPhys, true
}
