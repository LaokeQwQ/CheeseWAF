//go:build linux

package cli

import "golang.org/x/sys/unix"

// setTerminalEcho toggles ECHO on the terminal behind fd.
// Used by the setup wizard so password input is not echoed.
func setTerminalEcho(fd uintptr, on bool) error {
	attr, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	if err != nil {
		return err
	}
	if on {
		attr.Lflag |= unix.ECHO
	} else {
		attr.Lflag &^= unix.ECHO
	}
	return unix.IoctlSetTermios(int(fd), unix.TCSETS, attr)
}
