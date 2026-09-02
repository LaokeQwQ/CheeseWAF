//go:build windows

package cli

import "golang.org/x/sys/windows"

// setTerminalEcho toggles ENABLE_ECHO_INPUT on the console behind fd.
// Used by the setup wizard so password input is not echoed.
func setTerminalEcho(fd uintptr, on bool) error {
	var mode uint32
	handle := windows.Handle(fd)
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return err
	}
	if on {
		mode |= windows.ENABLE_ECHO_INPUT
	} else {
		mode &^= windows.ENABLE_ECHO_INPUT
	}
	return windows.SetConsoleMode(handle, mode)
}
