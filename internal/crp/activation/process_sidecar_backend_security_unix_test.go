//go:build !windows

package activation

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessSidecarBackendRejectsRelativeSymlinkAndUnsafePermissionPaths(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	base := processSidecarTestEntry(t, "normal")

	t.Run("relative executable", func(t *testing.T) {
		entry := cloneProcessRegistryEntry(base)
		entry.Executable = filepath.Base(executable)
		assertProcessSidecarRegistryRejected(t, entry)
	})

	t.Run("symlink executable", func(t *testing.T) {
		directory := canonicalSecureTestDirectory(t)
		link := filepath.Join(directory, "sidecar-link")
		if err := os.Symlink(executable, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		entry := cloneProcessRegistryEntry(base)
		entry.Executable = link
		entry.WorkingDirectory = directory
		assertProcessSidecarRegistryRejected(t, entry)
	})

	t.Run("symlink parent", func(t *testing.T) {
		root := canonicalSecureTestDirectory(t)
		realDirectory := filepath.Join(root, "real")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		copy := filepath.Join(realDirectory, "sidecar")
		copyExecutable(t, executable, copy, 0o700)
		link := filepath.Join(root, "linked")
		if err := os.Symlink(realDirectory, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		entry := cloneProcessRegistryEntry(base)
		entry.Executable = filepath.Join(link, "sidecar")
		entry.WorkingDirectory = link
		assertProcessSidecarRegistryRejected(t, entry)
	})

	t.Run("writable executable", func(t *testing.T) {
		directory := canonicalSecureTestDirectory(t)
		copy := filepath.Join(directory, "sidecar")
		copyExecutable(t, executable, copy, 0o777)
		entry := cloneProcessRegistryEntry(base)
		entry.Executable = copy
		entry.WorkingDirectory = directory
		assertProcessSidecarRegistryRejected(t, entry)
	})

	t.Run("writable parent", func(t *testing.T) {
		directory := canonicalSecureTestDirectory(t)
		copy := filepath.Join(directory, "sidecar")
		copyExecutable(t, executable, copy, 0o700)
		if err := os.Chmod(directory, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
		entry := cloneProcessRegistryEntry(base)
		entry.Executable = copy
		entry.WorkingDirectory = directory
		assertProcessSidecarRegistryRejected(t, entry)
	})
}

func TestProcessSidecarBackendRevalidatesExecutableBeforeEveryLaunch(t *testing.T) {
	directory := canonicalSecureTestDirectory(t)
	executable := filepath.Join(directory, "sidecar")
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	copyExecutable(t, source, executable, 0o700)
	entry := processSidecarTestEntry(t, "normal")
	entry.Executable = executable
	entry.WorkingDirectory = directory
	backend, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry: []ProcessSidecarRegistryEntry{entry}, Admission: allowProcessSidecarTestAdmission,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(executable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Start(context.Background(), processSidecarTestSpec()); !errors.Is(err, ErrProcessSidecarConfig) {
		t.Fatalf("Start() error = %v, want ErrProcessSidecarConfig", err)
	}
}

func assertProcessSidecarRegistryRejected(t *testing.T, entry ProcessSidecarRegistryEntry) {
	t.Helper()
	_, err := NewProcessSidecarBackend(ProcessSidecarBackendOptions{
		Registry: []ProcessSidecarRegistryEntry{entry}, Admission: allowProcessSidecarTestAdmission,
	})
	if !errors.Is(err, ErrProcessSidecarConfig) {
		t.Fatalf("NewProcessSidecarBackend() error = %v, want ErrProcessSidecarConfig", err)
	}
}

func canonicalSecureTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func copyExecutable(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(destination, mode); err != nil {
		t.Fatal(err)
	}
}
