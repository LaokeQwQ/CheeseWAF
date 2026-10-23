//go:build !windows

package activation

import (
	"os"
	"os/exec"
)

// configureProcessDataPlaneFiles passes the host->plugin read end as fd3 and
// the plugin->host write end as fd4. The parent closes these child ends after
// cmd.Start.
func configureProcessDataPlaneFiles(cmd *exec.Cmd, hostToPlugin, pluginToHost *os.File) error {
	cmd.ExtraFiles = []*os.File{hostToPlugin, pluginToHost}
	return nil
}
