//go:build !windows

package duckdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// writeFakeCLI installs a stand-in duckdb script so the executor's process
// handling is exercised without a real DuckDB binary. The script ignores
// --readonly/-json/-f and behaves like an oversized or failing child.
func writeFakeCLI(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "duckdb")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// Finding 5: the cap has to hold while the child runs. The fake CLI writes far
// more than the limit and only creates its marker when the whole stream was
// written successfully, so a marker proves the parent swallowed the entire
// stream instead of stopping at the limit. Old code (command.Output()) buffered
// everything first and applied the limit only afterwards.
func TestCLIExecutorCapsOutputWhileProcessRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child-finished")
	binary := writeFakeCLI(t, "#!/bin/sh\n"+
		"if head -c 4194304 /dev/zero | tr '\\0' 'x'; then : > '"+marker+"'; fi\n")
	executor := &CLIExecutor{Binary: binary}
	const limit = 1024
	start := time.Now()
	_, err := executor.Query(context.Background(), "SELECT 1", limit)
	if err == nil {
		t.Fatal("oversized output was accepted")
	}
	if want := fmt.Sprintf("duckdb output exceeds %d bytes", limit); !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want it to contain %q", err, want)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("child ran to completion: the whole stdout was buffered before the limit applied")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("oversized read took %s; the child was not cancelled", elapsed)
	}
}

// The child's stderr is captured by the executor itself now that stdout comes
// from a pipe, so it needs its own bound: a chatty failure must not be buffered
// without limit either.
func TestCLIExecutorBoundsChildStderr(t *testing.T) {
	binary := writeFakeCLI(t, "#!/bin/sh\n"+
		"head -c 1048576 /dev/zero | tr '\\0' 'e' >&2\n"+
		"exit 1\n")
	_, err := (&CLIExecutor{Binary: binary}).Query(context.Background(), "SELECT 1", DefaultMaxBytes)
	if err == nil {
		t.Fatal("failing child reported no error")
	}
	if !strings.Contains(err.Error(), "duckdb failed:") {
		t.Fatalf("err = %v, want a duckdb failure", err)
	}
	if len(err.Error()) > maxStderrBytes+64 {
		t.Fatalf("stderr was not bounded: %d bytes", len(err.Error()))
	}
}

// The bounded read must not change the success path: output under the limit is
// returned verbatim and a well-behaved child exits normally.
func TestCLIExecutorReturnsOutputUnderLimit(t *testing.T) {
	binary := writeFakeCLI(t, "#!/bin/sh\nprintf '[{\"severity\":\"high\"}]'\n")
	got, err := (&CLIExecutor{Binary: binary}).Query(context.Background(), "SELECT 1", DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `[{"severity":"high"}]` {
		t.Fatalf("output = %q", got)
	}
}

// A child that exits while a forked helper keeps the pipe open must not pin the
// caller past its deadline: the read has to be abandoned when the run context
// expires, otherwise a hung DuckDB wrapper blocks the analysis job forever.
func TestCLIExecutorHonoursTimeoutWithInheritedPipe(t *testing.T) {
	release := filepath.Join(t.TempDir(), "release")
	if err := syscall.Mkfifo(release, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// The helper inherits stdout/stderr and blocks on the FIFO until the test
	// opens the write end, so the parent's pipes stay open after the shell exits.
	binary := writeFakeCLI(t, "#!/bin/sh\n( read _ < '"+release+"' ) &\nexit 0\n")
	defer func() {
		if handle, err := os.OpenFile(release, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_, _ = handle.WriteString("\n")
			_ = handle.Close()
		}
	}()
	executor := &CLIExecutor{Binary: binary, Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err := executor.Query(context.Background(), "SELECT 1", DefaultMaxBytes)
	if err == nil {
		t.Fatal("blocked child reported no error")
	}
	if !strings.Contains(err.Error(), "timed out after") {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("deadline not honoured: took %s", elapsed)
	}
}
