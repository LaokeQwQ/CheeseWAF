//go:build !windows

package config

import "os"

func openConfigFile(path string) (*os.File, error) {
	return os.Open(path)
}
