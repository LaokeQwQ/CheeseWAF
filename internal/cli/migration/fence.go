package migration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
)

const (
	cutoverFenceVersion  = 1
	cutoverFenceFileName = "temporary-to-production.pending"
	cutoverFenceMaxBytes = 32 << 10
)

type cutoverFencePhase string

const (
	cutoverFencePending         cutoverFencePhase = "pending"
	cutoverFenceCommitAttempted cutoverFencePhase = "commit-attempted"
)

type cutoverFence struct {
	Version      int               `json:"version"`
	SnapshotID   string            `json:"snapshot_id"`
	ConfigDigest string            `json:"config_digest"`
	Phase        cutoverFencePhase `json:"phase"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// CheckPendingCutover rejects startup whenever a cutover marker exists. A
// malformed or insecure marker is also pending: serve must never guess that a
// partially committed migration is safe.
func CheckPendingCutover(dataDir string) error {
	if _, err := readCutoverFence(dataDir); err == nil {
		return ErrCutoverPending
	} else if errors.Is(err, os.ErrNotExist) {
		if _, recoveryErr := readRecoveryRecord(dataDir); errors.Is(recoveryErr, os.ErrNotExist) {
			return nil
		}
		return ErrCutoverPending
	}
	return ErrCutoverPending
}

func createCutoverFence(dataDir, snapshotID, configDigest string, now time.Time) error {
	if approval.ValidateIdentifier(snapshotID) != nil || len(configDigest) != 64 {
		return ErrRuntimeConfiguration
	}
	if _, err := readCutoverFence(dataDir); err == nil {
		return ErrCutoverPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrCutoverPending
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	fence := cutoverFence{Version: cutoverFenceVersion, SnapshotID: snapshotID, ConfigDigest: configDigest, Phase: cutoverFencePending, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	return writeCutoverFence(dataDir, fence)
}

func markCutoverCommitAttempted(dataDir, snapshotID string, now time.Time) error {
	fence, err := readCutoverFence(dataDir)
	if err != nil || fence.SnapshotID != snapshotID || fence.Phase != cutoverFencePending {
		return ErrCutoverPending
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	fence.Phase = cutoverFenceCommitAttempted
	fence.UpdatedAt = now.UTC()
	return writeCutoverFence(dataDir, fence)
}

func removeCutoverFence(dataDir, snapshotID string, committed bool) error {
	fence, err := readCutoverFence(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || fence.SnapshotID != snapshotID {
		return ErrCutoverPending
	}
	if !committed && fence.Phase != cutoverFencePending {
		return ErrCutoverPending
	}
	path, err := cutoverFencePath(dataDir)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if dir, openErr := os.Open(filepath.Dir(path)); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func readCutoverFence(dataDir string) (cutoverFence, error) {
	path, err := cutoverFencePath(dataDir)
	if err != nil {
		return cutoverFence{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return cutoverFence{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > cutoverFenceMaxBytes || info.Mode().Perm()&0o077 != 0 {
		return cutoverFence{}, ErrCutoverPending
	}
	file, err := os.Open(path)
	if err != nil {
		return cutoverFence{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, cutoverFenceMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return cutoverFence{}, readErr
	}
	if closeErr != nil {
		return cutoverFence{}, closeErr
	}
	if len(raw) > cutoverFenceMaxBytes {
		return cutoverFence{}, ErrCutoverPending
	}
	var fence cutoverFence
	if err := json.Unmarshal(raw, &fence); err != nil || fence.Version != cutoverFenceVersion || approval.ValidateIdentifier(fence.SnapshotID) != nil || len(fence.ConfigDigest) != 64 || fence.CreatedAt.IsZero() || fence.UpdatedAt.IsZero() || (fence.Phase != cutoverFencePending && fence.Phase != cutoverFenceCommitAttempted) {
		return cutoverFence{}, ErrCutoverPending
	}
	return fence, nil
}

func writeCutoverFence(dataDir string, fence cutoverFence) error {
	path, err := cutoverFencePath(dataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create migration state directory: %w", err)
	}
	raw, err := json.Marshal(fence)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writePrivateFileAtomic(path, raw, 0o600)
}

func cutoverFencePath(dataDir string) (string, error) {
	if dataDir == "" {
		return "", ErrRuntimeConfiguration
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", ErrRuntimeConfiguration
	}
	return filepath.Join(filepath.Clean(abs), "migration", cutoverFenceFileName), nil
}

func writePrivateFileAtomic(path string, raw []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}
