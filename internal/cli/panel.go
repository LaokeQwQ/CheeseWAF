package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var panelCmd = &cobra.Command{
	Use:   "cli",
	Short: "打开交互式 TUI 管理面板",
	Long:  `启动基于 bubbletea 的交互式终端管理面板，支持 ↑↓ 键导航菜单，可便捷执行 SSL 管理、用户管理、服务控制等操作。`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧀 CheeseWAF 管理面板")
		// TODO: Phase 1 实现 bubbletea TUI
		// 1. 初始化 bubbletea 程序
		// 2. 加载主菜单 (↑↓ 导航 + Enter 选择)
		// 3. 子菜单：SSL 管理 / 用户管理 / 服务控制 / 更新管理 / 快速诊断
		fmt.Println("⚠️  TUI 管理面板尚未实现，将在 Phase 1 完成")
	},
}
