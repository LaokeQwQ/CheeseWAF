//go:build !windows

package cli

func runServeCommand() error {
	return runServeInteractive()
}
