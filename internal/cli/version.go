package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "查看 CheeseWAF 版本和构建信息",
	Run: func(cmd *cobra.Command, args []string) {
		info := version.Current()
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "CheeseWAF %s\n", info.Version)
		fmt.Fprintf(out, "channel: %s\n", info.Channel)
		fmt.Fprintf(out, "edition: %s\n", info.Edition)
		fmt.Fprintf(out, "commit: %s\n", info.Commit)
		fmt.Fprintf(out, "build_time: %s\n", info.BuildTime)
		fmt.Fprintf(out, "go: %s\n", info.GoVersion)
		fmt.Fprintf(out, "platform: %s\n", info.Platform)
	},
}
