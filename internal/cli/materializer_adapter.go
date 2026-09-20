package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/materializer"
)

var (
	ErrMaterializerHandlerRequired    = errors.New("protection materializer handler is required")
	ErrMaterializerRuntimeRequired    = errors.New("protection materializer runtime callback is required")
	ErrMaterializerRuntimeDirRequired = errors.New("protection materializer runtime directory is required")
)

// NewProtectionPolicyMaterializer assembles the node-local materializer from
// the same Handler that serves the management API. It owns only the local
// snapshot, YAML and protection-runtime seams; proposal creation and
// coordinator ownership stay outside this constructor.
//
// The Handler must already carry a real OnProtectionChanged callback. A
// handler without that callback can persist YAML but cannot prove that the
// data-plane runtime was updated, so construction fails closed.
func NewProtectionPolicyMaterializer(h *handler.Handler, validator materializer.CurrentCommitValidator, runtimeDir string) (*materializer.ProtectionPolicyApplier, error) {
	if h == nil {
		return nil, ErrMaterializerHandlerRequired
	}
	if h.OnProtectionChanged == nil {
		return nil, ErrMaterializerRuntimeRequired
	}
	runtimeDir = strings.TrimSpace(runtimeDir)
	if runtimeDir == "" {
		return nil, ErrMaterializerRuntimeDirRequired
	}
	journal, err := materializer.NewJournalStore(filepath.Join(runtimeDir, "materializer"), materializer.Hooks{})
	if err != nil {
		return nil, fmt.Errorf("create protection materializer journal: %w", err)
	}
	applyRuntime := func(ctx context.Context, candidate *config.Config) error {
		if ctx == nil {
			return materializer.ErrNilContext
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return h.ApplyProtectionRuntime(candidate)
	}
	return materializer.NewProtectionPolicyApplier(materializer.ProtectionPolicyApplierOptions{
		Validator:        validator,
		Snapshot:         h.ConfigSnapshot,
		PreviousSnapshot: h.ConfigSnapshot,
		PersistConfig:    h.PersistMaterializedConfig,
		ApplyRuntime:     applyRuntime,
		RollbackRuntime:  applyRuntime,
		Journal:          journal,
	})
}
