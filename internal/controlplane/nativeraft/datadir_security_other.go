//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris

package nativeraft

import "os"

func checkOwned(string, os.FileInfo) error       { return errUnsupportedPlatform }
func checkOwnedOrRoot(string, os.FileInfo) error { return errUnsupportedPlatform }
func syncDirectory(string) error                 { return errUnsupportedPlatform }
