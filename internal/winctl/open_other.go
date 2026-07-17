//go:build !windows

package winctl

import (
	"fmt"
	"os/exec"
	"runtime"
)

func openURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open url: %w", err)
	}
	return nil
}

func openPath(path string) error {
	return openURL(path)
}
