package cli

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "优雅停止 CheeseWAF 服务",
	Run: func(cmd *cobra.Command, args []string) {
		pid, err := readPID()
		if err != nil {
			fmt.Println("CheeseWAF is not running")
			return
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			fmt.Printf("failed to find process %d: %v\n", pid, err)
			return
		}
		if err := proc.Signal(os.Interrupt); err != nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
		fmt.Printf("sent graceful stop signal to pid=%d\n", pid)
	},
}
