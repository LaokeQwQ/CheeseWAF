//go:build !windows

package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func serviceStopSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func listenServiceHangup(ctx context.Context, onHangup func()) {
	if onHangup == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				onHangup()
			}
		}
	}()
}
