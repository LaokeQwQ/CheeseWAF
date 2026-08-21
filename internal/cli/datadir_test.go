package cli

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRebaseUnderDataDirMapsPackagedRelativeRoots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "var", "lib", "cheesewaf")
	cases := map[string]string{
		"./data":                 root,
		"./data/run":             filepath.Join(root, "run"),
		"./data/cheesewaf.db":    filepath.Join(root, "cheesewaf.db"),
		"./data/certs/admin.crt": filepath.Join(root, "certs", "admin.crt"),
		"./logs/access.log":      filepath.Join(root, "logs", "access.log"),
		"./logs":                 filepath.Join(root, "logs"),
	}
	for in, want := range cases {
		got := rebaseUnderDataDir(in, root)
		if got != want {
			t.Fatalf("rebaseUnderDataDir(%q) = %q, want %q", in, got, want)
		}
	}
	abs := filepath.Join(root, "keep")
	if got := rebaseUnderDataDir(abs, root); got != abs {
		t.Fatalf("absolute path rewritten: %q", got)
	}
}

func TestApplyCLIDataDirOverridesYamlRelativeDataDir(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Setup.DataDir = "./data"
	cfg.Setup.RuntimeDir = "./data/run"
	cfg.Storage.SQLite.Path = "./data/cheesewaf.db"
	cfg.Logging.Output.File.Path = "./logs/access.log"
	cfg.Server.AdminTLS.CertFile = "./data/certs/admin.crt"
	if err := applyCLIDataDir(&cfg, root); err != nil {
		t.Fatal(err)
	}
	if cfg.Setup.DataDir != root {
		t.Fatalf("DataDir = %q, want %q", cfg.Setup.DataDir, root)
	}
	if cfg.Setup.RuntimeDir != filepath.Join(root, "run") {
		t.Fatalf("RuntimeDir = %q", cfg.Setup.RuntimeDir)
	}
	if cfg.Storage.SQLite.Path != filepath.Join(root, "cheesewaf.db") {
		t.Fatalf("sqlite = %q", cfg.Storage.SQLite.Path)
	}
	if cfg.Logging.Output.File.Path != filepath.Join(root, "logs", "access.log") {
		t.Fatalf("log = %q", cfg.Logging.Output.File.Path)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if cfg.Server.AdminTLS.CertFile != filepath.Join(root, "certs", "admin.crt") {
		t.Fatalf("cert = %q", cfg.Server.AdminTLS.CertFile)
	}
}
