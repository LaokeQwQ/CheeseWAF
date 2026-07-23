//go:build windows

package cli

import (
	"errors"
	"math"
	"os"

	"golang.org/x/sys/windows"
)

func processRunning(pid int) (bool, error) {
	// Windows OpenProcess takes a DWORD (uint32). Reject non-positive and
	// values that would truncate on the architecture-dependent int → uint32 cast
	// (CodeQL go/incorrect-integer-conversion; source is often strconv.Atoi on pid files).
	if pid <= 0 || pid > math.MaxUint32 {
		return false, nil
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false, nil
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return true, nil
		}
		return false, err
	}
	defer windows.CloseHandle(handle)
	code, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, err
	}
	return code == uint32(windows.WAIT_TIMEOUT), nil
}

func stopProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}
