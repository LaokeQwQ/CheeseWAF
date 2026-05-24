// Package cli implements the cobra command tree and BusyBox dispatch logic.
// When invoked as "cheesewaf", the default command is "serve" (starts WAF).
// When invoked as "waf-cli", the default command is the interactive TUI panel.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const (
	appName = "cheesewaf"
	cliName = "waf-cli"
)

var (
	appVersion = "0.1.0-dev"
	buildTime  = "unknown"
)

var rootCmd = &cobra.Command{
	Use:     appName,
	Short:   "CheeseWAF — 高性能 Web 应用防火墙",
	Long:    `CheeseWAF 是一个高性能、易用的 Web 应用防火墙 (WAF)，基于 Go 构建，支持语义分析引擎、AI 智能助手和 TUI 终端管理。`,
	Version: appVersion,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(panelCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(restartCmd)
}

// Execute dispatches the root command based on the executable name (BusyBox pattern).
// If called as "waf-cli", it defaults to the interactive TUI panel.
// If called as "cheesewaf" (or anything else), it defaults to starting the WAF server.
func Execute(execName string) {
	switch execName {
	case cliName:
		// waf-cli 直接执行 → 进入 TUI 管理面板
		if len(os.Args) == 1 {
			// 无子命令时直接进入 TUI
			panelCmd.Run(panelCmd, nil)
			return
		}
	case appName:
		// cheesewaf 无子命令时默认 serve
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
