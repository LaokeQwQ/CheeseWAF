package scheduler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		return result, errors.New("cleanup target is required")
	}
	target, err := validateManagedTarget(task.Target, task.ManagedRoots)
	if err != nil {
		return result, err
	}
	result.Target = target
	entries, err := os.ReadDir(target)
	if err != nil {
		return result, err
	}
	type fileInfo struct {
		path string
		mod  time.Time
	}
	var files []fileInfo
	for _, entry := range entries {
		if entry.IsDir() || !isManagedCleanupFile(task.Type, entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{path: filepath.Join(target, entry.Name()), mod: info.ModTime()})
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

func validateManagedTarget(target string, roots []string) (string, error) {
	if len(roots) == 0 {
		return "", errors.New("cleanup managed roots are not configured")
	}
	targetPath := resolveManagedTarget(target, roots)
	targetAbs, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return "", fmt.Errorf("resolve cleanup target: %w", err)
	}
	targetReal, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		return "", fmt.Errorf("resolve cleanup target links: %w", err)
	}
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		rootAbs, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			continue
		}
		rootReal, err := filepath.EvalSymlinks(rootAbs)
		if err != nil {
			rootReal = rootAbs
		}
		if pathWithinRoot(targetReal, rootReal) {
			return targetReal, nil
		}
	}
	return "", fmt.Errorf("cleanup target %q is outside CheeseWAF managed directories", target)
}

func resolveManagedTarget(target string, roots []string) string {
	cleanTarget := filepath.Clean(strings.TrimSpace(target))
	if filepath.IsAbs(cleanTarget) {
		return cleanTarget
	}
	for _, root := range roots {
		cleanRoot := filepath.Clean(strings.TrimSpace(root))
		if cleanRoot == "." || cleanRoot == "" {
			continue
		}
		if strings.EqualFold(cleanTarget, filepath.Base(cleanRoot)) {
			return cleanRoot
		}
	}
	for _, root := range roots {
		cleanRoot := filepath.Clean(strings.TrimSpace(root))
		if cleanRoot != "." && cleanRoot != "" {
			return filepath.Join(cleanRoot, cleanTarget)
		}
	}
	return cleanTarget
}

func pathWithinRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func isManagedCleanupFile(taskType, name string) bool {
	if strings.HasSuffix(name, managedBackupSuffix+".partial") {
		return true
	}
	if taskType == "backup" || strings.Contains(strings.ToLower(name), "backup") {
		return strings.HasSuffix(name, managedBackupSuffix)
	}
	return strings.HasPrefix(name, "cheesewaf-") || strings.HasPrefix(name, "access-") || strings.HasPrefix(name, "report-")
}
