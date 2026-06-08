package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func CleanupOldFiles(_ context.Context, task Task) error {
	if task.Target == "" {
		return nil
	}
	entries, err := os.ReadDir(task.Target)
	if err != nil {
		return err
	}
	type fileInfo struct {
		path string
		mod  time.Time
	}
	var files []fileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{path: filepath.Join(task.Target, entry.Name()), mod: info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].mod.After(files[j].mod)
	})
	keep := task.Keep
	if keep <= 0 {
		keep = 7
	}
	if len(files) <= keep {
		return nil
	}
	for _, file := range files[keep:] {
		if err := os.Remove(file.path); err != nil {
			return err
		}
	}
	return nil
}
