package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "优雅停止 CheeseWAF 服务",
	Run: func(cmd *cobra.Command, args []string) {
		snapshot, err := inspectServiceStatus()
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to inspect CheeseWAF status: %v\n", err)
			return
		}
		out := cmd.OutOrStdout()
		if !snapshot.HasPIDFile {
			fmt.Fprintf(out, "CheeseWAF is not running\n")
			return
		}
		if snapshot.Stale {
			removePID(snapshot.RuntimeDir)
			fmt.Fprintf(out, "removed stale pid file at %s\n", snapshot.PIDPath)
			return
		}
		if err := stopProcess(snapshot.PID); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "failed to stop process %d: %v\n", snapshot.PID, err)
			return
		}
		fmt.Fprintf(out, "sent stop signal to pid=%d\n", snapshot.PID)
	},
}
