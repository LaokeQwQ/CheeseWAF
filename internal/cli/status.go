package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "查看 CheeseWAF 服务运行状态",
	Run: func(cmd *cobra.Command, args []string) {
		pid, err := readPID()
		if err != nil {
			fmt.Println("CheeseWAF is not running (pid file not found)")
			return
		}
		fmt.Printf("CheeseWAF appears to be running, pid=%d\n", pid)
	},
}
