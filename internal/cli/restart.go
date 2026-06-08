package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "平滑重启 CheeseWAF 服务（零停机）",
	Run: func(cmd *cobra.Command, args []string) {
		stopCmd.Run(cmd, args)
		fmt.Println("start CheeseWAF again with: cheesewaf serve")
	},
}
