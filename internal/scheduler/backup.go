package scheduler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/fsguard"
)

const (
	managedBackupSuffix  = ".backup.json"
	maxBackupConfigBytes = 16 << 20
)

type BackupManifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source"`
	SHA256    string    `json:"sha256"`
	Content   []byte    `json:"content"`
}

func BackupConfig(configPath, dataDir string) TaskFunc {
	return func(ctx context.Context, task Task) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if configPath == "" {
			configPath = filepath.Join(dataDir, "cheesewaf.yaml")
		}
		backupRoot, targetRel, err := resolveBackupTarget(dataDir, task.Target)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(backupRoot, 0o700); err != nil {
			return fmt.Errorf("create backup root: %w", err)
		}
		rootInfo, err := os.Lstat(backupRoot)
		if err != nil {
			return fmt.Errorf("inspect backup root: %w", err)
		}
		if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
			return fmt.Errorf("backup root must be a non-symlink directory")
		}
		root, err := os.OpenRoot(backupRoot)
		if err != nil {
			return fmt.Errorf("open backup root: %w", err)
		}
		defer root.Close()
		if targetRel != "." {
			if err := root.MkdirAll(targetRel, 0o700); err != nil {
				return fmt.Errorf("create backup target: %w", err)
			}
			if err := rejectBackupSymlinkPath(root, targetRel); err != nil {
				return err
			}
		}

		src, err := os.Open(configPath)
		if err != nil {
			return err
		}
		defer src.Close()
		content, err := io.ReadAll(io.LimitReader(src, maxBackupConfigBytes+1))
		if err != nil {
			return err
		}
		if len(content) > maxBackupConfigBytes {
			return fmt.Errorf("configuration exceeds backup limit of %d bytes", maxBackupConfigBytes)
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		sum := sha256.Sum256(content)
		manifest, err := json.Marshal(BackupManifest{
			Version:   1,
			CreatedAt: time.Now().UTC(),
			Source:    filepath.Base(configPath),
			SHA256:    fmt.Sprintf("%x", sum[:]),
			Content:   content,
		})
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		name := fmt.Sprintf("cheesewaf-%s-%d%s", now.Format("20060102-150405"), now.UnixNano(), managedBackupSuffix)
		finalRel := filepath.Join(targetRel, name)
		tmpRel, dst, err := createBackupTemp(root, targetRel, name)
		if err != nil {
			return err
		}
		removePartial := true
		defer func() {
			_ = dst.Close()
			if removePartial {
				_ = root.Remove(tmpRel)
			}
		}()
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err = dst.Write(manifest); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err = dst.Sync(); err != nil {
			return err
		}
		if err = dst.Close(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err = root.Rename(tmpRel, finalRel); err != nil {
			return err
		}
		removePartial = false
		return syncBackupDir(root, targetRel)
	}
}

func resolveBackupTarget(dataDir, target string) (string, string, error) {
	rootAbs, err := filepath.Abs(filepath.Join(strings.TrimSpace(dataDir), "backups"))
	if err != nil {
		return "", "", fmt.Errorf("resolve backup root: %w", err)
	}
	rootAbs = filepath.Clean(rootAbs)
	target = strings.TrimSpace(target)
	if target == "" {
		return rootAbs, ".", nil
	}
	targetPath := filepath.Clean(target)
	if !filepath.IsAbs(targetPath) {
		candidateAbs, absErr := filepath.Abs(targetPath)
		if absErr == nil {
			if rel, relErr := filepath.Rel(rootAbs, candidateAbs); relErr == nil && (rel == "." || filepath.IsLocal(rel)) {
				targetPath = candidateAbs
			} else if filepath.IsLocal(targetPath) {
				targetPath = filepath.Join(rootAbs, targetPath)
			}
		}
	}
	targetPath = filepath.Clean(targetPath)
	if targetPath == rootAbs {
		return rootAbs, ".", nil
	}
	rel, err := fsguard.RelUnderRoot(rootAbs, targetPath)
	if err != nil {
		return "", "", fmt.Errorf("backup target is outside managed backup root: %w", err)
	}
	return rootAbs, rel, nil
}

func rejectBackupSymlinkPath(root *os.Root, rel string) error {
	current := ""
	for _, part := range strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' }) {
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := root.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect backup target: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("backup target must not contain symlinks")
		}
	}
	return nil
}

func createBackupTemp(root *os.Root, targetRel, finalName string) (string, *os.File, error) {
	for attempts := 0; attempts < 8; attempts++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, fmt.Errorf("create backup temp name: %w", err)
		}
		name := finalName + "." + hex.EncodeToString(random[:]) + ".partial"
		if targetRel != "." {
			name = filepath.Join(targetRel, name)
		}
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !os.IsExist(err) {
			return "", nil, fmt.Errorf("create backup temp file: %w", err)
		}
	}
	return "", nil, fmt.Errorf("create backup temp file: exhausted unique names")
}

func syncBackupDir(root *os.Root, rel string) error {
	dir, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		if strings.Contains(err.Error(), "Access is denied") {
			return nil
		}
		return err
	}
	return nil
}
