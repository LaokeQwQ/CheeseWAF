package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExecutableNameBusyBox(t *testing.T) {
	cases := map[string]string{
		"cheesewaf":                        "cheesewaf",
		"cheesewaf.exe":                    "cheesewaf",
		`C:\Program Files\bin\waf-cli.exe`: "waf-cli",
		"/usr/local/bin/waf-cli":           "waf-cli",
		"./cheesewaf":                      "cheesewaf",
	}
	for in, want := range cases {
		if got := executableName(in); got != want {
			t.Errorf("executableName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCLIBinaryVersionAndHelp(t *testing.T) {
	bin := buildPackageBinary(t, "cheesewaf")

	versionOut, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v\n%s", err, versionOut)
	}
	if !strings.Contains(string(versionOut), "CheeseWAF") {
		t.Fatalf("version output missing product name:\n%s", versionOut)
	}

	helpOut, err := exec.Command(bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("--help: %v\n%s", err, helpOut)
	}
	help := string(helpOut)
	for _, needle := range []string{"serve", "status", "stop", "cluster"} {
		if !strings.Contains(help, needle) {
			t.Fatalf("--help missing %q:\n%s", needle, help)
		}
	}
}

func TestCLIBinaryStatusDoesNotPanic(t *testing.T) {
	bin := buildPackageBinary(t, "cheesewaf")
	// Fresh temp data dir: status may report not-running, but must not panic.
	data := t.TempDir()
	cfg := filepath.Join(data, "cheesewaf.yaml")
	if err := os.WriteFile(cfg, []byte("setup: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "--config", cfg, "--data-dir", data, "status").CombinedOutput()
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("status panicked (err=%v):\n%s", err, out)
	}
	if len(out) == 0 && err != nil {
		t.Fatalf("status produced no output and failed: %v", err)
	}
}

func TestBusyBoxWafCLIHelp(t *testing.T) {
	src := buildPackageBinary(t, "cheesewaf")
	wafCLI := filepath.Join(t.TempDir(), "waf-cli")
	if runtime.GOOS == "windows" {
		wafCLI += ".exe"
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wafCLI, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(wafCLI, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("waf-cli --help: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "cheesewaf") && !strings.Contains(string(out), "CheeseWAF") {
		t.Fatalf("unexpected waf-cli help:\n%s", out)
	}
}

func buildPackageBinary(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./%s: %v\n%s", name, err, out)
	}
	return bin
}
