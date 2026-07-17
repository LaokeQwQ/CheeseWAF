package cli

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestPackLogsCreatesZipWithManifest(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logPath, []byte(`{"action":"pass"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cheesewaf.yaml")
	cfg := config.Default()
	cfg.Logging.Output.File.Path = logPath
	cfg.Setup.DataDir = dir
	if err := config.Save(cfgPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	clilang.Configure("en", dir)
	outDir := filepath.Join(dir, "out")
	path, count, err := packLogs(cfgPath, dir, "", outDir, "test-bundle")
	if err != nil {
		t.Fatalf("packLogs: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected manifest + at least one log, count=%d", count)
	}
	if !strings.HasSuffix(path, "test-bundle.zip") {
		t.Fatalf("path=%q", path)
	}
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var names []string
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "MANIFEST.txt") {
		t.Fatalf("missing manifest in %v", names)
	}
}
