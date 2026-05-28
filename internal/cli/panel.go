package cli

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli/tui"
	"github.com/spf13/cobra"
)

var panelCmd = &cobra.Command{
	Use:   "cli",
	Short: "打开交互式 TUI 管理面板",
	Long:  `启动基于 bubbletea 的交互式终端管理面板，支持 ↑↓ 键导航菜单，可便捷执行 SSL 管理、用户管理、服务控制等操作。`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := tui.Run(tui.Options{ConfigPath: configPath, DataDir: dataDir}); err != nil {
			fmt.Println(err)
		}
	},
}
