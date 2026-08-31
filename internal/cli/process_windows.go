//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

var (
	processStopGracePeriod = 2 * time.Second
	processStopPoll        = 25 * time.Millisecond
)

func signalServiceHangup(string) error { return nil }

func processRunning(pid int) (bool, error) {
	// Windows OpenProcess takes a DWORD (uint32). Reject non-positive values and
	// anything that would truncate on the architecture-dependent int → uint32 cast.
	if pid <= 0 || int64(pid) > 4294967295 {
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

func processIdentityMatches(pid int, expected string) (bool, error) {
	if pid <= 0 || int64(pid) > 4294967295 {
		return false, nil
	}
	if strings.TrimSpace(expected) == "" {
		return true, nil
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return false, nil
		}
		return false, err
	}
	defer windows.CloseHandle(handle)
	var buffer [windows.MAX_PATH]uint16
	length := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &length); err != nil {
		return false, err
	}
	actual := strings.TrimSpace(windows.UTF16ToString(buffer[:length]))
	return strings.EqualFold(canonicalPath(actual), canonicalPath(expected)), nil
}

func stopProcess(pid int, expected ...string) error {
	if pid <= 0 || int64(pid) > 4294967295 {
		return fmt.Errorf("invalid process pid %d", pid)
	}
	identity := ""
	if len(expected) > 0 {
		identity = strings.TrimSpace(expected[0])
	}
	if identity != "" {
		matches, err := processIdentityMatches(pid, identity)
		if err != nil {
			return err
		}
		if !matches {
			return fmt.Errorf("process identity mismatch for pid %d", pid)
		}
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Kill(); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return err
	}
	deadline := time.Now().Add(processStopGracePeriod)
	for time.Now().Before(deadline) {
		running, err := processRunning(pid)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		time.Sleep(processStopPoll)
	}
	return fmt.Errorf("process %d did not terminate", pid)
}
