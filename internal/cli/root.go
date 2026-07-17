// Package cli implements the cobra command tree and BusyBox dispatch logic.
// When invoked as "cheesewaf", the default command is "serve" (starts WAF).
// When invoked as "waf-cli", the default command is the interactive TUI panel.
package cli

import (
	"fmt"
	"os"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
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
	cliLang    = ""
)

var rootCmd = newRootCommand()

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     appName,
		Short:   clilang.T("root.short"),
		Long:    clilang.T("root.long"),
		Version: version.Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Resolve language after flags are parsed (flag > env > data-dir > system).
			clilang.Configure(cliLang, dataDir)
			// Refresh short descriptions that depend on locale for help of leaf commands.
			cmd.Root().Short = clilang.T("root.short")
			cmd.Root().Long = clilang.T("root.long")
		},
	}
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", configPath, "Path to cheesewaf.yaml")
	cmd.PersistentFlags().StringVar(&dataDir, "data-dir", dataDir, "Runtime data directory")
	cmd.PersistentFlags().StringVar(&cliLang, "lang", "", "CLI language (en|zh-CN); default from install/env/system")
	cmd.SetVersionTemplate(`{{printf "CheeseWAF %s\n" .Version}}`)
	cmd.AddCommand(serveCmd)
	cmd.AddCommand(panelCmd)
	cmd.AddCommand(statusCmd)
	cmd.AddCommand(newHealthcheckCommand())
	cmd.AddCommand(stopCmd)
	cmd.AddCommand(restartCmd)
	cmd.AddCommand(userCmd)
	cmd.AddCommand(newClusterCommand())
	cmd.AddCommand(versionCmd)
	cmd.AddCommand(newLangCommand())
	cmd.AddCommand(newLogsCommand())
	return cmd
}

// Execute dispatches the root command based on the executable name (BusyBox pattern).
// If called as "waf-cli", it defaults to the interactive TUI panel.
// If called as "cheesewaf" (or anything else), it defaults to starting the WAF server.
func Execute(execName string) {
	// Early language bootstrap so version/help before PersistentPreRun still look reasonable.
	clilang.Configure(os.Getenv(clilang.EnvVar), dataDir)
	info := version.Current()
	rootCmd.Version = info.Version + " (" + info.Channel + ", " + info.BuildTime + ")"
	rootCmd.Short = clilang.T("root.short")
	rootCmd.Long = clilang.T("root.long")
	switch execName {
	case cliName:
		if len(os.Args) == 1 {
			panelCmd.Run(panelCmd, nil)
			return
		}
	case appName:
		if len(os.Args) == 1 {
			// Delegate to cobra so RunE/flags are handled properly.
			os.Args = append(os.Args, "serve")
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
