package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "查看 CheeseWAF 服务运行状态",
	Run: func(cmd *cobra.Command, args []string) {
		snapshot, err := inspectServiceStatus()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to inspect CheeseWAF status: %v\n", err)
			return
		}
		out := cmd.OutOrStdout()
		info := version.Current()
		fmt.Fprintf(out, "CheeseWAF %s (%s)\n", info.Version, info.Channel)
		switch {
		case !snapshot.HasPIDFile:
			fmt.Fprintf(out, "CheeseWAF is not running (pid file not found at %s)\n", snapshot.PIDPath)
		case snapshot.Running:
			fmt.Fprintf(out, "CheeseWAF is running, pid=%d\n", snapshot.PID)
		case snapshot.Stale:
			fmt.Fprintf(out, "CheeseWAF is not running (stale pid file at %s, pid=%d)\n", snapshot.PIDPath, snapshot.PID)
		default:
			fmt.Fprintf(out, "CheeseWAF status is unknown (pid file at %s, pid=%d)\n", snapshot.PIDPath, snapshot.PID)
		}
	},
}
