//go:build windows

package cli

import (
	"context"
	"os"
)

func serviceStopSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

func listenServiceHangup(context.Context, func()) {}
