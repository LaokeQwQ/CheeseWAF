package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
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
	runtime := &handlerMaterializerRuntime{handler: h, journal: journal}
	return materializer.NewProtectionPolicyApplier(materializer.ProtectionPolicyApplierOptions{
		Validator:        validator,
		Snapshot:         h.ConfigSnapshot,
		PreviousSnapshot: h.ConfigSnapshot,
		PersistConfig:    h.PersistMaterializedConfig,
		Runtime:          runtime,
		Journal:          journal,
	})
}

type handlerMaterializerRuntime struct {
	handler *handler.Handler
	journal *materializer.JournalStore
}

func (r *handlerMaterializerRuntime) Query(ctx context.Context, target, previous materializer.RuntimeRequest) (materializer.RuntimeState, error) {
	if ctx == nil {
		return materializer.RuntimeStateUnknown, materializer.ErrNilContext
	}
	current, err := r.handler.ConfigSnapshot(ctx)
	if err != nil {
		return materializer.RuntimeStateUnknown, err
	}
	currentDigest, err := materializer.ConfigDigest(current)
	if err != nil {
		return materializer.RuntimeStateUnknown, err
	}
	receipt, receiptErr := r.journal.LoadRuntimeReceiptContext(ctx)
	if receiptErr != nil && !errors.Is(receiptErr, materializer.ErrReceiptNotFound) {
		return materializer.RuntimeStateUnknown, receiptErr
	}
	if currentDigest == target.ConfigDigest || receiptErr == nil && receipt.Matches(target) {
		// On process restart the Handler/proxy is constructed from the durable
		// candidate YAML before materialization resumes. Seal that observed
		// target as the exact runtime receipt so recovery never replays it.
		if currentDigest == target.ConfigDigest && (receiptErr != nil || !receipt.Matches(target)) {
			targetReceipt, receiptBuildErr := materializer.NewRuntimeReceipt(target)
			if receiptBuildErr != nil {
				return materializer.RuntimeStateUnknown, receiptBuildErr
			}
			if saveErr := r.journal.SaveRuntimeReceiptContext(ctx, targetReceipt); saveErr != nil {
				return materializer.RuntimeStateUnknown, saveErr
			}
		}
		return materializer.RuntimeStateTarget, nil
	}
	if currentDigest == previous.ConfigDigest {
		if receiptErr != nil || receipt.Matches(previous) || receipt.Commit != target.Commit {
			return materializer.RuntimeStatePrevious, nil
		}
	}
	return materializer.RuntimeStateUnknown, nil
}

func (r *handlerMaterializerRuntime) Apply(ctx context.Context, request materializer.RuntimeRequest) error {
	if ctx == nil {
		return materializer.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.handler.ApplyProtectionRuntime(request.Config); err != nil {
		return err
	}
	receipt, err := materializer.NewRuntimeReceipt(request)
	if err != nil {
		return err
	}
	// The synchronous runtime callback may return after the deadline that woke
	// the caller. Its successful side effect must still be sealed while the
	// directory lease is retained, otherwise restart would see an ambiguous
	// runtime_intent and could replay the side effect.
	return r.journal.SaveRuntimeReceiptContext(context.WithoutCancel(ctx), receipt)
}
