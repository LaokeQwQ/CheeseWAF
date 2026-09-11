package kms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func SaveKeyringFile(ctx context.Context, path string, keyring *EncryptedKeyring) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if keyring == nil || !validPath(path) {
		return ErrInvalidConfig
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return ErrInvalidConfig
		}
		return ErrInvalidConfig
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidConfig
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ErrInvalidConfig
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm()&0022 != 0 {
		return ErrInvalidConfig
	}
	blob, err := keyring.MarshalBinary()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cheesewaf-keyring-")
	if err != nil {
		return ErrInvalidConfig
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return ErrInvalidConfig
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return ErrInvalidConfig
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ErrInvalidConfig
	}
	if err := tmp.Close(); err != nil {
		return ErrInvalidConfig
	}
	if err := os.Link(tmpPath, path); err != nil {
		return ErrInvalidConfig
	}
	if err := os.Remove(tmpPath); err != nil {
		return ErrInvalidConfig
	}
	return syncDir(dir)
}

func LoadKeyringFile(ctx context.Context, path string, source RootKeySource) (*EncryptedKeyring, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if !validPath(path) || source == nil {
		return nil, ErrInvalidConfig
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0077 != 0 {
		return nil, ErrInvalidConfig
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return OpenEncryptedKeyring(ctx, source, blob)
}

func validPath(path string) bool {
	clean := filepath.Clean(path)
	return path != "" && clean != "." && !strings.ContainsRune(path, '\x00')
}
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return ErrInvalidConfig
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return ErrInvalidConfig
	}
	return nil
}
