//go:build !windows

package cli

import (
	"os"
	"syscall"
)

func serviceStopSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
