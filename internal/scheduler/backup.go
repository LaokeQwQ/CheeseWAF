package scheduler

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

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
		name := fmt.Sprintf("cheesewaf-%s.yaml", time.Now().UTC().Format("20060102-150405"))
		dst, err := os.OpenFile(filepath.Join(task.Target, name), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
		if err != nil {
			return err
		}
		defer dst.Close()
		_, err = io.Copy(dst, src)
		return err
	}
}
