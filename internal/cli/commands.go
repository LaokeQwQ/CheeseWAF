package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "查看 CheeseWAF 服务运行状态",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("⚠️  status 命令尚未实现，将在 Phase 1 完成")
	},
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "优雅停止 CheeseWAF 服务",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("⚠️  stop 命令尚未实现，将在 Phase 1 完成")
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "平滑重启 CheeseWAF 服务（零停机）",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("⚠️  restart 命令尚未实现，将在 Phase 1 完成")
	},
}
