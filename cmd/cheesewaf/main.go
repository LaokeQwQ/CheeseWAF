package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli"
)

func main() {
	// BusyBox mode: executable basename selects default command.
	// cheesewaf → serve; waf-cli → TUI panel.
	cli.Execute(executableName(os.Args[0]))
}

func executableName(arg0 string) string {
	return strings.TrimSuffix(filepath.Base(arg0), ".exe")
}
