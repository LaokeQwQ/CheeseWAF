package crp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRuntimeLeaseHelper is launched in a separate process by
// TestRuntimeLeaseIsExclusiveAcrossProcesses. Keeping the helper in the
// package test binary makes the lock contract executable without requiring a
// second production command or a platform-specific test harness.
func TestRuntimeLeaseHelper(t *testing.T) {
	if os.Getenv("CHEESEWAF_RUNTIME_LEASE_HELPER") != "1" {
		return
	}
	root := os.Getenv("CHEESEWAF_RUNTIME_LEASE_ROOT")
	lease, err := acquireRuntimeLease(root)
	if err != nil {
		fmt.Fprintf(os.Stdout, "error: %v\n", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, "locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = lease.Close()
	os.Exit(0)
}

func TestRuntimeLeaseIsExclusiveAcrossProcesses(t *testing.T) {
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeLeaseHelper$")
	cmd.Env = append(os.Environ(),
		"CHEESEWAF_RUNTIME_LEASE_HELPER=1",
		"CHEESEWAF_RUNTIME_LEASE_ROOT="+root,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("lease helper did not report ownership: %v", err)
	}
	if strings.TrimSpace(line) != "locked" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("lease helper output=%q", line)
	}
	if _, err := acquireRuntimeLease(root); !errors.Is(err, ErrRuntimeBusy) {
		t.Fatalf("second process lease err=%v, want ErrRuntimeBusy", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("lease helper exit: %v", err)
	}
	lease, err := acquireRuntimeLease(root)
	if err != nil {
		t.Fatalf("lease after owner exit: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(root, runtimeLockFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("lock sentinel type/mode=%v", info.Mode())
	}
}

func TestRuntimeStoreMergesStateFromAStoreOpenedBeforeAnotherCommit(t *testing.T) {
	root := t.TempDir()
	options := RuntimeStoreOptions{
		Clock:       func() time.Time { return time.Unix(0, 0).UTC() },
		HealthCheck: HealthCheckFunc(func(RuntimeRecord) error { return nil }),
		Revalidate:  RuntimeRevalidateFunc(func(RuntimeRecord) error { return nil }),
	}
	first, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	pkgA, importedA := runtimePackage(t, "stale-store-a", "1.0.0", 1, []byte("artifact-a"))
	pkgB, importedB := runtimePackage(t, "stale-store-b", "1.0.0", 1, []byte("artifact-b"))
	if _, err := first.Stage(pkgA, importedA); err != nil {
		t.Fatalf("first stage: %v", err)
	}
	if _, err := second.Stage(pkgB, importedB); err != nil {
		t.Fatalf("second stage from stale store: %v", err)
	}
	reopened, err := NewRuntimeStore(root, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Staged("stale-store-a"); err != nil {
		t.Fatalf("first state lost after stale-store commit: %v", err)
	}
	if _, err := reopened.Staged("stale-store-b"); err != nil {
		t.Fatalf("second state missing after stale-store commit: %v", err)
	}
}
