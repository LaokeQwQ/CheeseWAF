//go:build windows

package scheduler

func syncDir(string) error {
	// Windows does not support fsync on directory handles opened by os.Open.
	// The backup file itself is flushed before the atomic rename.
	return nil
}
