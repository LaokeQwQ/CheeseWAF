package duckdb

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const cliTestModeEnv = "CHEESEWAF_DUCKDB_CLI_TEST_MODE"

// Reuse the test executable as a fake DuckDB CLI without a shell or an
// installed DuckDB dependency. The real CLI arguments are intentionally ignored.
func TestMain(m *testing.M) {
	switch os.Getenv(cliTestModeEnv) {
	case "json":
		_, _ = io.WriteString(os.Stdout, `[{"severity":"info","count":1}]`)
		os.Exit(0)
	case "overflow":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("x", DefaultMaxBytes+1))
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "hold-stdout":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "inherited-output":
		child := exec.Command(os.Args[0])
		child.Env = append(os.Environ(), cliTestModeEnv+"=hold-stdout")
		child.Stdout = os.Stdout
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("CHEESEWAF_DUCKDB_CLI_TEST_PID"), []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
			_ = child.Process.Kill()
			os.Exit(2)
		}
		_ = child.Process.Release()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestCLIExecutorReturnsJSON(t *testing.T) {
	t.Setenv(cliTestModeEnv, "json")
	executor := CLIExecutor{Binary: os.Args[0]}
	output, err := executor.Query(context.Background(), "SELECT 1", DefaultMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != `[{"severity":"info","count":1}]` {
		t.Fatalf("output = %q", output)
	}
}

func TestCLIExecutorCancelsOversizedOutput(t *testing.T) {
	t.Setenv(cliTestModeEnv, "overflow")
	executor := CLIExecutor{Binary: os.Args[0], Timeout: 15 * time.Second}
	started := time.Now()
	output, err := executor.Query(context.Background(), "SELECT 1", DefaultMaxBytes)
	if !errors.Is(err, errCLIOutputTooLarge) {
		t.Fatalf("error = %v, want output limit error", err)
	}
	if output != nil {
		t.Fatalf("returned %d oversized output bytes", len(output))
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("overflow took %s; the CLI was not canceled promptly", elapsed)
	}
}

func TestCLIExecutorBoundsInheritedOutputWait(t *testing.T) {
	t.Setenv(cliTestModeEnv, "inherited-output")
	pidPath := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("CHEESEWAF_DUCKDB_CLI_TEST_PID", pidPath)
	t.Cleanup(func() {
		data, err := os.ReadFile(pidPath)
		if err != nil {
			t.Errorf("read descendant PID: %v", err)
			return
		}
		pid, err := strconv.Atoi(string(data))
		if err != nil {
			t.Errorf("parse descendant PID: %v", err)
			return
		}
		if child, err := os.FindProcess(pid); err == nil {
			_ = child.Kill()
			_ = child.Release()
		}
	})
	executor := CLIExecutor{Binary: os.Args[0], Timeout: 15 * time.Second}
	started := time.Now()
	// The bound is what matters: the call must finish promptly whether the
	// implementation reports ErrWaitDelay or closes the read side itself.
	if _, err := executor.Query(context.Background(), "SELECT 1", DefaultMaxBytes); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("error = %v, want success or inherited-pipe wait limit", err)
	}
	if elapsed := time.Since(started); elapsed >= 5*time.Second {
		t.Fatalf("inherited output pipe delayed completion by %s", elapsed)
	}
}
