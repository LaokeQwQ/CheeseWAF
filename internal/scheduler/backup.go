package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const managedBackupSuffix = ".backup.json"

type BackupManifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source"`
	SHA256    string    `json:"sha256"`
	Content   []byte    `json:"content"`
}

func BackupConfig(configPath, dataDir string) TaskFunc {
	return func(_ context.Context, task Task) error {
		if configPath == "" {
			configPath = filepath.Join(dataDir, "cheesewaf.yaml")
		}
		if task.Target == "" {
			task.Target = filepath.Join(dataDir, "backups")
		}
		if err := os.MkdirAll(task.Target, 0o750); err != nil {
			return err
		}
		src, err := os.Open(configPath)
		if err != nil {
			return err
		}
		defer src.Close()
		content, err := io.ReadAll(src)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		manifest, err := json.Marshal(BackupManifest{Version: 1, CreatedAt: time.Now().UTC(), Source: filepath.Base(configPath), SHA256: fmt.Sprintf("%x", sum[:]), Content: content})
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		name := fmt.Sprintf("cheesewaf-%s-%d%s", now.Format("20060102-150405"), now.UnixNano(), managedBackupSuffix)
		finalPath := filepath.Join(task.Target, name)
		tmpPath := finalPath + ".partial"
		dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
		if err != nil {
			return err
		}
		removePartial := true
		defer func() {
			_ = dst.Close()
			if removePartial {
				_ = os.Remove(tmpPath)
			}
		}()
		if _, err = dst.Write(manifest); err != nil {
			return err
		}
		if err = dst.Sync(); err != nil {
			return err
		}
		if err = dst.Close(); err != nil {
			return err
		}
		if err = os.Rename(tmpPath, finalPath); err != nil {
			return err
		}
		removePartial = false
		return syncDir(task.Target)
	}
}
