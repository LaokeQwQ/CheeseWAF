package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type CleanupResult struct {
	Target  string `json:"target"`
	Keep    int    `json:"keep"`
	Scanned int    `json:"scanned"`
	Removed int    `json:"removed"`
}

func CleanupOldFiles(_ context.Context, task Task) error {
	_, err := CleanupOldFilesWithResult(task)
	return err
}

func CleanupOldFilesWithResult(task Task) (CleanupResult, error) {
	result := CleanupResult{Target: task.Target, Keep: task.Keep}
	if task.Target == "" {
		return result, nil
	}
	entries, err := os.ReadDir(task.Target)
	if err != nil {
		return result, err
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
	result.Scanned = len(files)
	sort.Slice(files, func(i, j int) bool {
		return files[i].mod.After(files[j].mod)
	})
	keep := task.Keep
	if keep <= 0 {
		keep = 7
	}
	result.Keep = keep
	if len(files) <= keep {
		return result, nil
	}
	for _, file := range files[keep:] {
		if err := os.Remove(file.path); err != nil {
			return result, err
		}
		result.Removed++
	}
	return result, nil
}
