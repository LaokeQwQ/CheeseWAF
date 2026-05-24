package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "启动 CheeseWAF 服务",
	Long:  `启动 WAF 反向代理服务，监听数据平面端口 (:80/:443) 和管理平面端口 (127.0.0.1:9443)。`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🧀 CheeseWAF 正在启动...")
		// TODO: Phase 1 实现完整的服务启动逻辑
		// 1. 加载配置
		// 2. 初始化数据库
		// 3. 启动检测引擎
		// 4. 启动反向代理
		// 5. 启动管理 API
		fmt.Println("⚠️  serve 命令尚未实现，将在 Phase 1 完成")
	},
}
