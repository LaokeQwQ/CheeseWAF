//go:build !windows

package activation

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const processSidecarStartCleanupMarker = "CHEESEWAF_PROCESS_START_CLEANUP_MARKER"

func TestProcessSidecarStartCleanupHelper(t *testing.T) {
	marker := os.Getenv(processSidecarStartCleanupMarker)
	if marker == "" {
		return
	}
	if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(90)
	}
	// An oversized initial request is rejected before anything is written to
	// stdin. Without Start's failure cleanup, this real child waits forever.
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestProcessSidecarBackendReapsStartRejectedBeforeProtocolWrite(t *testing.T) {
	marker := filepath.Join(canonicalSecureTestDirectory(t), "child.pid")
	entry := processSidecarTestEntry(t, "normal")
	entry.Args = []string{"-test.run=^TestProcessSidecarStartCleanupHelper$"}
	entry.Environment = map[string]string{processSidecarStartCleanupMarker: marker}
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry: []ProcessSidecarRegistryEntry{entry}, Admission: allowProcessSidecarTestAdmission,
		MaxMessageBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	childPID := 0
	t.Cleanup(func() {
		if childPID > 0 {
			// Only the PID recorded by this test's helper may be cleaned up.
			_ = syscall.Kill(childPID, syscall.SIGKILL)
		}
		closeContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := backend.Close(closeContext); err != nil {
			t.Errorf("backend cleanup: %v", err)
		}
	})

	process, err := backend.Start(t.Context(), processSidecarTestSpec())
	if process != nil || !errors.Is(err, ErrProcessSidecarProtocol) || !strings.Contains(err.Error(), "request exceeds 256 bytes") {
		t.Fatalf("Start() = process:%v error:%v, want initial request size rejection", process, err)
	}

	// Killing immediately after exec may prevent the helper from writing its
	// marker. Observe long enough for an incorrectly retained child to start,
	// including when the test binary is built with the race detector.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		raw, readErr := os.ReadFile(marker)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			t.Fatal(readErr)
		}
		if len(raw) != 0 {
			childPID, err = strconv.Atoi(string(raw))
			if err != nil || childPID <= 0 || childPID == os.Getpid() {
				childPID = 0
				t.Fatalf("invalid helper PID marker %q", raw)
			}
			if err := syscall.Kill(childPID, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("failed Start left helper PID %d alive: %v", childPID, err)
			}
			childPID = 0
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := backend.Close(t.Context()); err != nil {
		t.Fatalf("Close() after failed Start: %v", err)
	}
}
