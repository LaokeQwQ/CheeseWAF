//go:build !windows && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package cli

import "errors"

// errEchoUnsupported is returned on platforms without a termios/console binding.
// The setup wizard then reads the password with echo enabled and warns the user.
var errEchoUnsupported = errors.New("terminal echo control is unsupported on this platform")

func setTerminalEcho(fd uintptr, on bool) error {
	return errEchoUnsupported
}
