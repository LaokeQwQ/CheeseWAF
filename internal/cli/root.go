// Package cli implements the cobra command tree and BusyBox dispatch logic.
// When invoked as "cheesewaf", the default command is "serve" (starts WAF).
// When invoked as "waf-cli", the default command is the interactive TUI panel.
package cli

import (
	"fmt"
	"os"

	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/spf13/cobra"
)

const (
	appName = "cheesewaf"
	cliName = "waf-cli"
)

var (
	configPath = "./data/cheesewaf.yaml"
	dataDir    = "./data"
)

var rootCmd = newRootCommand()

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     appName,
		Short:   "CheeseWAF - high-performance web application firewall",
		Long:    "CheeseWAF is a high-performance Web Application Firewall (WAF) built with Go, semantic detection, AI assistant, and TUI management.",
		Version: version.Version,
	}
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", configPath, "Path to cheesewaf.yaml")
	cmd.PersistentFlags().StringVar(&dataDir, "data-dir", dataDir, "Runtime data directory")
	cmd.AddCommand(serveCmd)
	cmd.AddCommand(panelCmd)
	cmd.AddCommand(statusCmd)
	cmd.AddCommand(newHealthcheckCommand())
	cmd.AddCommand(stopCmd)
	cmd.AddCommand(restartCmd)
	cmd.AddCommand(userCmd)
	cmd.AddCommand(newClusterCommand())
	cmd.AddCommand(versionCmd)
	return cmd
}

// Execute dispatches the root command based on the executable name (BusyBox pattern).
// If called as "waf-cli", it defaults to the interactive TUI panel.
// If called as "cheesewaf" (or anything else), it defaults to starting the WAF server.
func Execute(execName string) {
	info := version.Current()
	rootCmd.Version = info.Version + " (" + info.Channel + ", " + info.BuildTime + ")"
	switch execName {
	case cliName:
		if len(os.Args) == 1 {
			panelCmd.Run(panelCmd, nil)
			return
		}
	case appName:
		if len(os.Args) == 1 {
			serveCmd.Run(serveCmd, nil)
			return
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
