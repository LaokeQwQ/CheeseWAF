package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cli"
)

func main() {
	// BusyBox 模式：根据可执行文件名切换行为
	// cheesewaf → 启动 WAF 服务 (默认 serve)
	// waf-cli  → 进入 TUI 管理面板
	execName := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")

	cli.Execute(execName)
}
