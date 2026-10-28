//go:build !windows

package materializer

import "os"

func durableRename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }
