package nativeraft

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var errUnsupportedPlatform = errors.New("native-raft filesystem security is unsupported on this platform")

func validateSupportedPlatform(goos string) error {
	switch goos {
	case "aix", "darwin", "dragonfly", "freebsd", "illumos", "linux", "netbsd", "openbsd", "solaris":
		return nil
	default:
		return fmt.Errorf("%w: %s", errUnsupportedPlatform, goos)
	}
}

func secureDataDir(path string) (string, error) {
	if err := validateSupportedPlatform(runtime.GOOS); err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("data directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve data directory: %w", err)
	}
	abs = filepath.Clean(abs)
	if err := ensureSecureDirectoryPath(abs); err != nil {
		return "", err
	}
	return abs, nil
}

func ensureSecureDirectoryPath(path string) error {
	volume := filepath.VolumeName(path)
	rest := path[len(volume):]
	if rest == "" {
		rest = string(filepath.Separator)
	}
	current := volume
	if filepath.IsAbs(rest) {
		current += string(filepath.Separator)
		rest = rest[1:]
	}
	if current == "" {
		current = "."
	}
	parts := []string{}
	for _, part := range splitPath(rest) {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect data directory %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("data directory %q is not a real directory", current)
		}
		return checkSecureDirectory(current, info, true)
	}
	for i, part := range parts {
		if current == string(filepath.Separator) || current == volume+string(filepath.Separator) {
			current = filepath.Join(current, part)
		} else {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return fmt.Errorf("create data directory component %q: %w", current, err)
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("inspect data directory component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if trustedDarwinAlias(current) {
				current = filepath.Join("/private", strings.TrimPrefix(current, string(filepath.Separator)))
				info, err = os.Lstat(current)
				if err != nil {
					return fmt.Errorf("inspect canonical data directory component %q: %w", current, err)
				}
			} else {
				return fmt.Errorf("data directory component %q is a symlink", current)
			}
		}
		if !info.IsDir() {
			return fmt.Errorf("data directory component %q is not a directory", current)
		}
		last := i == len(parts)-1
		if last {
			if err := checkSecureDirectory(current, info, true); err != nil {
				return err
			}
		} else if err := checkSecureDirectory(current, info, false); err != nil {
			return err
		}
	}
	return nil
}

func trustedDarwinAlias(path string) bool {
	return runtime.GOOS == "darwin" && (path == "/var" || path == "/tmp")
}

func splitPath(path string) []string {
	var parts []string
	for path != "" {
		part := filepath.Base(path)
		if part == path {
			return append([]string{part}, parts...)
		}
		parts = append([]string{part}, parts...)
		path = filepath.Dir(path)
	}
	return parts
}

func checkSecureDirectory(path string, info os.FileInfo, final bool) error {
	if final {
		if err := checkOwned(path, info); err != nil {
			return err
		}
	} else if err := checkOwnedOrRoot(path, info); err != nil {
		return err
	}
	perm := info.Mode().Perm()
	if final {
		if perm != 0o700 {
			return fmt.Errorf("data directory %q has insecure permissions mode %04o; want 0700", path, perm)
		}
		return nil
	}
	if perm&0o022 != 0 && !(info.Mode()&os.ModeSticky != 0 && perm&0o002 != 0) {
		return fmt.Errorf("data directory ancestor %q is group/world writable (mode %04o)", path, perm)
	}
	return nil
}

func checkSecureRegularFile(path string, wantPerm os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("secure file %q is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("secure file %q is not a regular file", path)
	}
	if err := checkOwned(path, info); err != nil {
		return err
	}
	if info.Mode().Perm() != wantPerm {
		return fmt.Errorf("secure file %q has mode %04o; want %04o", path, info.Mode().Perm(), wantPerm)
	}
	return nil
}

func atomicWriteSecure(path string, data []byte, perm os.FileMode) error {
	if err := validateSupportedPlatform(runtime.GOOS); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensureSecureDirectoryPath(dir); err != nil {
		return err
	}
	if err := checkSecureRegularFile(path, perm); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".native-raft-*.tmp")
	if err != nil {
		return fmt.Errorf("create secure temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod secure temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write secure file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync secure file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close secure file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("atomically replace secure file: %w", err)
	}
	return syncDirectory(dir)
}
