package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show CheeseWAF version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		// Keep Short localized when command is executed after PersistentPreRun.
		cmd.Short = clilang.T("version.short")
		info := version.Current()
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "CheeseWAF %s\n", info.Version)
		fmt.Fprintf(out, "channel: %s\n", info.Channel)
		fmt.Fprintf(out, "edition: %s\n", info.Edition)
		fmt.Fprintf(out, "commit: %s\n", info.Commit)
		fmt.Fprintf(out, "build_time: %s\n", info.BuildTime)
		fmt.Fprintf(out, "go: %s\n", info.GoVersion)
		fmt.Fprintf(out, "platform: %s\n", info.Platform)
		fmt.Fprintf(out, "cli_lang: %s\n", clilang.Current())
	},
}
