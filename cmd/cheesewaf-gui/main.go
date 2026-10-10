// CheeseWAF local service controller (Windows GUI / desktop shell).
//
// Scope (implementation_plan):
//   - start / stop / restart CheeseWAF via CLI semantics
//   - show process status + paths
//   - optional login autostart
//   - open Web console / config directory
//
// This is NOT a second management backend. Complex config stays in Web/TUI/CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/LaokeQwQ/CheeseWAF/internal/winctl"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("cheesewaf-gui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configFromEnv := strings.TrimSpace(os.Getenv("CHEESEWAF_CONFIG"))
	dataDirFromEnv := strings.TrimSpace(os.Getenv("CHEESEWAF_DATA_DIR"))
	defaultConfig := envOrDefault("CHEESEWAF_CONFIG", "./data/config/cheesewaf.yaml")
	defaultDataDir := envOrDefault("CHEESEWAF_DATA_DIR", "./data")
	if exe, err := os.Executable(); err == nil && runningInsideMacApp(exe) && configFromEnv == "" && dataDirFromEnv == "" {
		defaultConfig, defaultDataDir = applyMacAppLaunchPaths(exe)
	}
	configPath := fs.String("config", defaultConfig, "Path to cheesewaf.yaml")
	dataDir := fs.String("data-dir", defaultDataDir, "Runtime data directory")
	binary := fs.String("binary", "", "Path to cheesewaf binary (default: sibling of this GUI)")
	adminURL := fs.String("admin-url", "", "Web console URL (default: derive from config)")
	listen := fs.String("listen", "127.0.0.1:17943", "Loopback control UI listen address")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctl, err := winctl.New(winctl.Options{
		Binary:     *binary,
		ConfigPath: *configPath,
		DataDir:    *dataDir,
		AdminURL:   *adminURL,
		Listen:     *listen,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("CheeseWAF controller on http://%s/ (loopback only)\n", *listen)
	if err := ctl.ListenAndServe(ctx); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func envOrDefault(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
