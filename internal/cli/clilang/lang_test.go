package clilang

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeAndDetect(t *testing.T) {
	if got := Normalize("zh_CN.UTF-8"); got != "zh-CN" {
		t.Fatalf("Normalize zh_CN = %q", got)
	}
	if got := Normalize("en-US"); got != "en" {
		t.Fatalf("Normalize en-US = %q", got)
	}
}

func TestConfigurePriorityFlagOverEnvAndFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PrefFile), []byte("en\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvVar, "zh-CN")
	if got := Configure("en", dir); got != "en" {
		t.Fatalf("flag should win, got %q", got)
	}
	if got := Configure("", dir); got != "zh-CN" {
		t.Fatalf("env should win over file, got %q", got)
	}
	t.Setenv(EnvVar, "")
	if got := Configure("", dir); got != "en" {
		t.Fatalf("file preference, got %q", got)
	}
}

func TestSetAndT(t *testing.T) {
	dir := t.TempDir()
	if err := Set("zh-CN", dir); err != nil {
		t.Fatal(err)
	}
	if Current() != "zh-CN" {
		t.Fatalf("current=%q", Current())
	}
	if msg := T("version.short"); msg == "" || msg == "version.short" {
		t.Fatalf("missing zh translation: %q", msg)
	}
	raw, err := os.ReadFile(filepath.Join(dir, PrefFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := Normalize(string(raw)); got != "zh-CN" {
		t.Fatalf("persisted=%q", string(raw))
	}
}
