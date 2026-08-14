package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunningInsideMacApp(t *testing.T) {
	app := "/Applications/CheeseWAF.app/Contents/MacOS/CheeseWAF"
	got := runningInsideMacApp(app)
	want := runtime.GOOS == "darwin"
	if got != want {
		t.Fatalf("runningInsideMacApp(app) = %v, want %v", got, want)
	}
	if runningInsideMacApp("/usr/local/bin/cheesewaf-gui") {
		t.Fatal("plain binary is not a Mac app")
	}
}

func TestSeedFileIfMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.yaml")
	dest := filepath.Join(dir, "out", "dest.yaml")
	if err := os.WriteFile(src, []byte("listen: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := seedFileIfMissing(src, dest); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "listen: test\n" {
		t.Fatalf("seeded body = %q", body)
	}
	if err := os.WriteFile(dest, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := seedFileIfMissing(src, dest); err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep\n" {
		t.Fatalf("existing dest was overwritten: %q", body)
	}
}
