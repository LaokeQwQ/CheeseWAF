package cli

import (
	"context"
	"errors"
	"os/signal"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "启动 CheeseWAF 服务",
	Long:  `启动 WAF 反向代理服务；实际监听地址、TLS 与管理面暴露范围均以 --config 指定的配置为准。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServeCommand()
	},
}

func runServeInteractive() error {
	ctx, stop := signal.NotifyContext(context.Background(), serviceStopSignals()...)
	defer stop()
	if err := runServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
