package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/clilang"
	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show CheeseWAF service status",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Short = clilang.T("status.short")
		snapshot, err := inspectServiceStatus()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), clilang.T("status.inspect_failed")+"\n", err)
			return
		}
		out := cmd.OutOrStdout()
		info := version.Current()
		fmt.Fprintf(out, "CheeseWAF %s (%s)\n", info.Version, info.Channel)
		fmt.Fprintf(out, "cli_lang: %s\n", clilang.Current())
		switch {
		case !snapshot.HasPIDFile:
			fmt.Fprintf(out, clilang.T("status.not_running")+"\n", snapshot.PIDPath)
		case snapshot.Running:
			fmt.Fprintf(out, clilang.T("status.running")+"\n", snapshot.PID)
		case snapshot.Stale:
			fmt.Fprintf(out, clilang.T("status.stale")+"\n", snapshot.PIDPath, snapshot.PID)
		default:
			fmt.Fprintf(out, clilang.T("status.unknown")+"\n", snapshot.PIDPath, snapshot.PID)
		}
	},
}
