//go:build !windows

package winctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsAutostartEnabled reports XDG autostart desktop entry presence on Unix.
func IsAutostartEnabled() bool {
	path, err := xdgAutostartPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// SetAutostart writes or removes a user-level XDG autostart entry.
func SetAutostart(enable bool, exe string, args []string) error {
	path, err := xdgAutostartPath()
	if err != nil {
		return err
	}
	if !enable {
		_ = os.Remove(path)
		return nil
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cmd := abs
	for _, a := range args {
		cmd += " " + shellQuote(a)
	}
	body := fmt.Sprintf("[Desktop Entry]\nType=Application\nName=CheeseWAF Controller\nExec=%s\nX-GNOME-Autostart-enabled=true\n", cmd)
	return os.WriteFile(path, []byte(body), 0o644)
}

func xdgAutostartPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "autostart", "cheesewaf-controller.desktop"), nil
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t'\"\\") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
