package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGUIRejectsNonLoopbackListen(t *testing.T) {
	code := run([]string{
		"-listen", "0.0.0.0:17943",
		"-config", filepath.Join(t.TempDir(), "c.yaml"),
		"-data-dir", t.TempDir(),
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 for non-loopback listen", code)
	}
}

func TestGUIHelpFlag(t *testing.T) {
	// flag.ContinueOnError returns flag.ErrHelp for -h → exit 2.
	code := run([]string{"-h"})
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 for -h", code)
	}
}

func TestGUIBinaryBuildsAndRejectsBadListen(t *testing.T) {
	bin := buildGUIBinary(t)
	cmd := exec.Command(bin,
		"-listen", "8.8.8.8:1",
		"-data-dir", t.TempDir(),
		"-config", filepath.Join(t.TempDir(), "x.yaml"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected non-zero exit for non-loopback listen, got success:\n%s", out)
	}
	if len(out) == 0 {
		t.Fatalf("expected error output for bad listen (err=%v)", err)
	}
}

func TestGUIBinaryHelp(t *testing.T) {
	bin := buildGUIBinary(t)
	cmd := exec.Command(bin, "-h")
	out, err := cmd.CombinedOutput()
	// flag -h exits with status 2 and usage text on stderr (merged here).
	if err == nil {
		t.Fatalf("expected non-zero exit for -h, got success:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "listen") && !strings.Contains(text, "config") {
		t.Fatalf("help text missing expected flags:\n%s", text)
	}
}

func buildGUIBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "cheesewaf-gui")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build gui: %v\n%s", err, out)
	}
	return bin
}
