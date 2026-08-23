package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	pidLeaseFileName = "cheesewaf.pid.lock"
	pidFileMode      = 0o640
	pidLeaseMode     = 0o600
)

type servicePIDRecord struct {
	PID        int       `json:"pid"`
	Executable string    `json:"executable,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
}

type pidLease struct {
	file       *os.File
	runtimeDir string
	pid        int
	mu         sync.Mutex
	closed     bool
}

func acquirePIDLease(runtimeDir string) (*pidLease, error) {
	if strings.TrimSpace(runtimeDir) == "" {
		return nil, errors.New("runtime directory is empty")
	}
	runtimeDir = filepath.Clean(runtimeDir)
	if err := os.MkdirAll(runtimeDir, 0o750); err != nil {
		return nil, fmt.Errorf("create runtime directory: %w", err)
	}
	path := filepath.Join(runtimeDir, pidLeaseFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, pidLeaseMode)
	if err != nil {
		return nil, fmt.Errorf("open service lease: %w", err)
	}
	if err := lockPIDLeaseFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("service is already running or lease is unavailable: %w", err)
	}
	return &pidLease{file: file, runtimeDir: runtimeDir}, nil
}

func (l *pidLease) Write(pid int) error {
	if l == nil || l.file == nil {
		return errors.New("service lease is not open")
	}
	if pid <= 0 {
		return errors.New("invalid service pid")
	}
	executable := ""
	if path, err := executablePath(); err == nil {
		executable = canonicalPath(path)
	}
	record := servicePIDRecord{PID: pid, Executable: executable, StartedAt: time.Now().UTC()}
	contents, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode service pid: %w", err)
	}
	contents = append(contents, '\n')
	if err := writePIDRecordAtomic(pidPath(l.runtimeDir), contents); err != nil {
		return err
	}
	l.mu.Lock()
	l.pid = pid
	l.mu.Unlock()
	return nil
}

func (l *pidLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	pid := l.pid
	l.mu.Unlock()
	if pid > 0 {
		_ = removePIDIfMatches(l.runtimeDir, pid)
	}
	unlockErr := unlockPIDLeaseFile(l.file)
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func writePID(runtimeDir string) error {
	lease, err := acquirePIDLease(runtimeDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	return lease.Write(os.Getpid())
}

func readPIDRecord(runtimeDir string) (servicePIDRecord, error) {
	raw, err := os.ReadFile(pidPath(runtimeDir))
	if err != nil {
		return servicePIDRecord{}, err
	}
	var record servicePIDRecord
	if err := json.Unmarshal(raw, &record); err == nil && record.PID > 0 {
		return record, nil
	}
	// Accept the old numeric format so upgrades can cleanly recognize a stale
	// file instead of treating it as an unreadable service state.
	pid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil || pid <= 0 {
		return servicePIDRecord{}, fmt.Errorf("invalid service pid file: %w", err)
	}
	return servicePIDRecord{PID: int(pid)}, nil
}

func writePIDRecordAtomic(path string, contents []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cheesewaf.pid.*.tmp")
	if err != nil {
		return fmt.Errorf("create pid file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(pidFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod pid file: %w", err)
	}
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write pid file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync pid file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close pid file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("publish pid file: %w", err)
	}
	return nil
}

func removePIDIfMatches(runtimeDir string, pid int) error {
	record, err := readPIDRecord(runtimeDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if record.PID != pid {
		return nil
	}
	return os.Remove(pidPath(runtimeDir))
}

func canonicalPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	return filepath.Clean(path)
}
