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
	Long:  `启动 WAF 反向代理服务，监听数据平面端口 (:80/:443) 和管理平面端口 (127.0.0.1:9443)。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), serviceStopSignals()...)
		defer stop()
		if err := runServe(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	},
}
