package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "优雅停止 CheeseWAF 服务",
	RunE:  runStopCommand,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runStopCommand(cmd, args); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
	},
}

func runStopCommand(cmd *cobra.Command, _ []string) error {
	snapshot, err := inspectServiceStatus()
	if err != nil {
		return fmt.Errorf("failed to inspect CheeseWAF status: %w", err)
	}
	out := cmd.OutOrStdout()
	if !snapshot.HasPIDFile {
		fmt.Fprintf(out, "CheeseWAF is not running\n")
		return nil
	}
	if snapshot.Stale {
		if err := removePIDIfMatches(snapshot.RuntimeDir, snapshot.PID); err != nil {
			return fmt.Errorf("remove stale pid file %s: %w", snapshot.PIDPath, err)
		}
		fmt.Fprintf(out, "removed stale pid file at %s\n", snapshot.PIDPath)
		return nil
	}
	record, err := readPIDRecord(snapshot.RuntimeDir)
	if err != nil {
		return fmt.Errorf("read service identity: %w", err)
	}
	if err := stopProcess(snapshot.PID, record.Executable); err != nil {
		return fmt.Errorf("failed to stop process %d: %w", snapshot.PID, err)
	}
	if err := removePIDIfMatches(snapshot.RuntimeDir, snapshot.PID); err != nil {
		return fmt.Errorf("remove stopped pid file: %w", err)
	}
	fmt.Fprintf(out, "stopped process pid=%d\n", snapshot.PID)
	return nil
}
