//go:build !unix && !windows

package captcha

import "os"

func statCapSecretFile(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func openCapSecretFile(path string) (*os.File, error) {
	return os.Open(path)
}
