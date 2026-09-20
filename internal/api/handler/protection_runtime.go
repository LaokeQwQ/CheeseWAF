package handler

import (
	"fmt"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

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
