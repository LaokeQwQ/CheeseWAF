//go:build windows

package winctl

import (
	"os/exec"
	"syscall"
)

func openURL(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}

func openPath(path string) error {
	cmd := exec.Command("explorer", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
