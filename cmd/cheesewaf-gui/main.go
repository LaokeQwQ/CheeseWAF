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
	configPath := flag.String("config", "./data/cheesewaf.yaml", "Path to cheesewaf.yaml")
	dataDir := flag.String("data-dir", "./data", "Runtime data directory")
	binary := flag.String("binary", "", "Path to cheesewaf binary (default: sibling of this GUI)")
	adminURL := flag.String("admin-url", "https://127.0.0.1:9443/__cheesewaf-entry", "Web console URL")
	listen := flag.String("listen", "127.0.0.1:17943", "Loopback control UI listen address")
	flag.Parse()

	ctl, err := winctl.New(winctl.Options{
		Binary:     *binary,
		ConfigPath: *configPath,
		DataDir:    *dataDir,
		AdminURL:   *adminURL,
		Listen:     *listen,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("CheeseWAF controller on http://%s/ (loopback only)\n", *listen)
	if err := ctl.ListenAndServe(ctx); err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
