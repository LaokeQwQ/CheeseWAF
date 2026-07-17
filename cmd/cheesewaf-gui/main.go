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
	"syscall"

	"github.com/LaokeQwQ/CheeseWAF/internal/winctl"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("cheesewaf-gui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	configPath := fs.String("config", "./data/cheesewaf.yaml", "Path to cheesewaf.yaml")
	dataDir := fs.String("data-dir", "./data", "Runtime data directory")
	binary := fs.String("binary", "", "Path to cheesewaf binary (default: sibling of this GUI)")
	adminURL := fs.String("admin-url", "https://127.0.0.1:9443/__cheesewaf-entry", "Web console URL")
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
