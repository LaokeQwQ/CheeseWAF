//go:build windows

package winctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const autostartValueName = "CheeseWAFController"

// IsAutostartEnabled reports whether HKCU Run contains the controller entry.
func IsAutostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(autostartValueName)
	return err == nil
}

// SetAutostart enables or disables login autostart for the given executable.
// No secrets are written — only the binary path and safe CLI flags.
func SetAutostart(enable bool, exe string, args []string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("open Run key: %w", err)
	}
	defer k.Close()
	if !enable {
		_ = k.DeleteValue(autostartValueName)
		return nil
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("autostart binary: %w", err)
	}
	quoted := make([]string, 0, 1+len(args))
	quoted = append(quoted, quoteWinArg(abs))
	for _, a := range args {
		quoted = append(quoted, quoteWinArg(a))
	}
	return k.SetStringValue(autostartValueName, strings.Join(quoted, " "))
}

func quoteWinArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
