//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	processStopGracePeriod = 2 * time.Second
	processStopPoll        = 25 * time.Millisecond
)

func signalServiceHangup(runtimeDir string) error {
	record, err := readPIDRecord(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if record.PID <= 0 {
		return nil
	}
	running, err := processRunning(record.PID)
	if err != nil {
		return err
	}
	if !running {
		return nil
	}
	if err := syscall.Kill(record.PID, syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal service hangup: %w", err)
	}
	return nil
}

func processRunning(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return false, err
}

func processIdentityMatches(pid int, expected string) (bool, error) {
	expected = canonicalPath(expected)
	if pid <= 0 || expected == "" {
		return pid > 0, nil
	}
	procPath := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	if actual, err := os.Readlink(procPath); err == nil {
		actual = strings.TrimSuffix(actual, " (deleted)")
		return canonicalPath(actual) == expected, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	// macOS and some hardened Unix environments do not mount /proc. `ps`
	// still gives us a process-name check; the held PID lease supplies the
	// stronger ownership guarantee for CheeseWAF instances.
	output, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect process identity: %w", err)
	}
	actualName := strings.TrimSpace(string(output))
	if index := strings.IndexByte(actualName, '\n'); index >= 0 {
		actualName = strings.TrimSpace(actualName[:index])
	}
	return actualName == filepath.Base(expected), nil
}

func waitForProcessExit(pid int, expected string, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		running, err := processRunning(pid)
		if err != nil {
			return false, err
		}
		if !running {
			return true, nil
		}
		if expected != "" {
			matches, err := processIdentityMatches(pid, expected)
			if err != nil {
				return false, err
			}
			if !matches {
				return true, nil
			}
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		time.Sleep(processStopPoll)
	}
}

func stopProcess(pid int, expected ...string) error {
	if pid <= 0 {
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
	if err := proc.Signal(os.Interrupt); err == nil {
		if exited, waitErr := waitForProcessExit(pid, identity, processStopGracePeriod); exited {
			return nil
		} else if waitErr != nil {
			return waitErr
		}
	} else if !errors.Is(err, syscall.ESRCH) {
		// Continue to TERM below. Some service supervisors do not permit SIGINT.
		firstErr := err
		if termErr := proc.Signal(syscall.SIGTERM); termErr != nil && !errors.Is(termErr, syscall.ESRCH) {
			return fmt.Errorf("interrupt: %v; term: %w", firstErr, termErr)
		}
	}
	if exited, waitErr := waitForProcessExit(pid, identity, processStopGracePeriod); exited {
		return nil
	} else if waitErr != nil {
		return waitErr
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("send terminate signal: %w", err)
	}
	if exited, waitErr := waitForProcessExit(pid, identity, processStopGracePeriod); exited {
		return nil
	} else if waitErr != nil {
		return waitErr
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("send kill signal: %w", err)
	}
	if exited, waitErr := waitForProcessExit(pid, identity, processStopGracePeriod); exited {
		return nil
	} else if waitErr != nil {
		return waitErr
	}
	return fmt.Errorf("process %d did not terminate after interrupt, term, and kill", pid)
}
