//go:build windows

package activation

import (
	"errors"
	"os"
	"os/exec"
)

// Windows does not support exec.Cmd.ExtraFiles. The named-pipe transport is a
// separate gate; until it lands, do not claim data-plane support on Windows.
func configureProcessDataPlaneFiles(cmd *exec.Cmd, hostToPlugin, pluginToHost *os.File) error {
	return errors.New("process data-plane pipes are not supported on Windows")
}
