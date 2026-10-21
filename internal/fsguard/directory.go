package fsguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateDirectoryUnderRoot permits a directory that does not exist yet, but
// rejects existing symlinks from root through candidate. Every metadata lookup
// is relative to a pinned os.Root, including the check of root itself.
func ValidateDirectoryUnderRoot(root, candidate string) error {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(candidate) == "" {
		return fmt.Errorf("root and directory are required")
	}
	rootAbs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return err
	}
	candidateAbs, err := filepath.Abs(strings.TrimSpace(candidate))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("directory must be inside the configured root")
	}
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if err := SafePathComponent(part); err != nil {
				return err
			}
		}
	}

	// A fresh install may have neither root nor its parent yet. Open the nearest
	// existing ancestor, then inspect the missing suffix without creating it.
	anchorPath := filepath.Dir(rootAbs)
	var anchor *os.Root
	for {
		anchor, err = os.OpenRoot(anchorPath)
		if err == nil {
			break
		}
		parent := filepath.Dir(anchorPath)
		if !os.IsNotExist(err) || parent == anchorPath {
			return fmt.Errorf("open managed directory ancestor: %w", err)
		}
		anchorPath = parent
	}
	defer func() { _ = anchor.Close() }()
	walk, err := filepath.Rel(anchorPath, candidateAbs)
	if err != nil || !filepath.IsLocal(walk) {
		return fmt.Errorf("directory must be inside the opened ancestor")
	}
	if walk == "." {
		return nil
	}
	for _, part := range strings.Split(walk, string(filepath.Separator)) {
		info, err := anchor.Lstat(part)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("managed directory contains symlink: %s", part)
		}
		if !info.IsDir() {
			return fmt.Errorf("managed directory component is not a directory: %s", part)
		}
		next, err := anchor.OpenRoot(part)
		if err != nil {
			return err
		}
		openedInfo, err := next.Stat(".")
		if err != nil || !os.SameFile(info, openedInfo) {
			_ = next.Close()
			return fmt.Errorf("managed directory changed while checking component: %s", part)
		}
		_ = anchor.Close()
		anchor = next
	}
	return nil
}
