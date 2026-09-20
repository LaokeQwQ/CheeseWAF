package handler

import (
	"context"
	"errors"
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// ErrMaterializedConfigPath identifies a handler that cannot provide the
// durable YAML boundary required by the node-local materializer.
var ErrMaterializedConfigPath = errors.New("materialized configuration path is required")

// ConfigSnapshot returns an isolated copy of the current complete local
// configuration. The materializer uses this as its read boundary; callers
// must not receive the atomic request snapshot itself because Config contains
// maps and slices that would otherwise be mutable through aliasing.
func (h *Handler) ConfigSnapshot(ctx context.Context) (*config.Config, error) {
	if h == nil {
		return nil, fmt.Errorf("handler is unavailable")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current := h.currentConfig()
	if current == nil {
		return nil, fmt.Errorf("configuration is unavailable")
	}
	snapshot, err := config.Clone(current)
	if err != nil {
		return nil, fmt.Errorf("clone configuration snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// PersistMaterializedConfig validates and persists a complete local candidate
// for the node-local materializer. It deliberately does not publish the
// candidate or apply runtime side effects: the orchestrator owns the
// YAML/runtime/journal ordering and compensation boundary.
//
// The candidate is cloned before validation so EnsureRuntimeSecrets and any
// validation normalization cannot mutate the caller's materializer state.
func (h *Handler) PersistMaterializedConfig(ctx context.Context, candidate *config.Config) error {
	if h == nil {
		return fmt.Errorf("handler is unavailable")
	}
	if ctx == nil {
		return fmt.Errorf("context is nil")
	}
	if candidate == nil {
		return fmt.Errorf("configuration is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if h.ConfigPath == "" {
		return ErrMaterializedConfigPath
	}
	isolated, err := config.Clone(candidate)
	if err != nil {
		return fmt.Errorf("clone materialized configuration: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Keep the same lock order and write gates as the existing Handler config
	// mutation paths. In particular, this adapter must not bypass a frozen
	// configuration or cluster protection mode.
	h.configPersistMu.Lock()
	defer h.configPersistMu.Unlock()
	h.configMutationMu.Lock()
	defer h.configMutationMu.Unlock()
	if h.configWriteFrozen {
		return fmt.Errorf("configuration writes are frozen: %s", h.configFreezeReason)
	}
	if ok, reason := h.clusterConfigWritable("zh-CN"); !ok {
		return fmt.Errorf("cluster protection mode: %s", reason)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := config.EnsureRuntimeSecrets(isolated); err != nil {
		return err
	}
	if err := config.Validate(isolated); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return h.persistConfigCandidateLocked(isolated)
}

// ApplyProtectionRuntime validates a complete local candidate and applies only
// its protection runtime snapshot. Persistence and control-plane coordination
// stay with the caller's transaction boundary.
func (h *Handler) ApplyProtectionRuntime(candidate *config.Config) error {
	if h == nil {
		return fmt.Errorf("handler is unavailable")
	}
	if candidate == nil {
		return fmt.Errorf("configuration is unavailable")
	}
	if err := config.Validate(candidate); err != nil {
		return err
	}

	// The runtime callback may retain or mutate its argument asynchronously.
	// Give it an isolated protection snapshot so it cannot alias the mutation
	// candidate or the caller's rollback state.
	snapshot, err := config.Clone(&config.Config{Protection: candidate.Protection})
	if err != nil {
		return fmt.Errorf("clone protection runtime snapshot: %w", err)
	}
	return h.notifyProtectionConfigChanged(snapshot.Protection)
}
