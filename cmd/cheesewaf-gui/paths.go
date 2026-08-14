package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func runningInsideMacApp(exe string) bool {
	if runtime.GOOS != "darwin" || strings.TrimSpace(exe) == "" {
		return false
	}
	return strings.Contains(filepath.ToSlash(exe), ".app/Contents/MacOS/")
}

func macAppSupportDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "CheeseWAF")
}

func macAppResourcesDir(exe string) string {
	return filepath.Clean(filepath.Join(filepath.Dir(exe), "..", "Resources"))
}

func applyMacAppLaunchPaths(exe string) (configPath, dataDir string) {
	support := macAppSupportDir()
	if support == "" {
		return filepath.Join(".", "data", "cheesewaf.yaml"), filepath.Join(".", "data")
	}
	configPath = filepath.Join(support, "cheesewaf.yaml")
	dataDir = filepath.Join(support, "data")
	resources := macAppResourcesDir(exe)
	webDir := filepath.Join(resources, "web")
	if _, err := os.Stat(filepath.Join(webDir, "index.html")); err == nil {
		_ = os.Setenv("CHEESEWAF_WEB_DIR", webDir)
	}
	_ = seedFileIfMissing(filepath.Join(resources, "configs", "cheesewaf.yaml"), configPath)
	_ = os.MkdirAll(dataDir, 0o755)
	return configPath, dataDir
}

func seedFileIfMissing(src, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return nil
	}
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, body, 0o644)
}
