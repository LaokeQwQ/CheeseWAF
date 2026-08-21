//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
)

func serviceStopSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func ignoreServiceHangup() {
	signal.Ignore(syscall.SIGHUP)
}
