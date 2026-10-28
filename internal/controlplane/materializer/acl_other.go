//go:build !windows

package materializer

func ensurePrivateWindowsACL(string) error { return nil }
