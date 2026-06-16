//go:build windows

package cli

import "os"

func serviceStopSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}
