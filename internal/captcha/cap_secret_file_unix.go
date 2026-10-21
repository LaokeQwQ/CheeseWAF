//go:build unix

package captcha

import (
	"os"

	"golang.org/x/sys/unix"
)

func statCapSecretFile(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func openCapSecretFile(path string) (*os.File, error) {
	// A regular file can be replaced after Lstat. Nonblocking no-follow open
	// keeps a swapped FIFO from waiting for a writer before handle validation.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
