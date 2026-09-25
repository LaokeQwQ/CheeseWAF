package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/desiredstate"
)

var errProtectionPolicyMaterializationFailed = errors.New("protection policy materialization is frozen after a previous failure")

const protectionPolicyPreviewTTL = 5 * time.Minute

// Materialization holds the StateMachine current-commit read lease across
// local YAML, runtime and journal I/O. Keep that critical section bounded even
// when the originating HTTP request has already completed or disconnected.
const protectionPolicyMaterializationTimeout = 30 * time.Second

// protectionPolicyMaterializer is the intentionally small runtime contract
// used by the composition root. The concrete implementation retains journal
// and exact-commit validation semantics in the materializer package.
type protectionPolicyMaterializer interface {
	ApplyCommitted(context.Context, controlplane.Commit) error
}

type protectionPolicyPreview struct {
	actor    string
	before   config.ProtectionPolicyConfig
	after    config.ProtectionPolicyConfig
	epoch    controlplane.Epoch
	revision controlplane.Revision
	expires  time.Time
}

// protectionPolicyCoordinatorConsumer is the production-only lifecycle owner
// for policy writes. It combines immutable Handler reads, server nonces,
// durable/consensus coordination, node-local materialization, and post-runtime
// request-snapshot publication. There is deliberately no local-write fallback.
type protectionPolicyCoordinatorConsumer struct {
	mu           sync.Mutex
	handler      *handler.Handler
	machine      *controlplane.StateMachine
	coordinator  *controlplane.Coordinator
	service      *desiredstate.ProtectionPolicyCoordinatorService
	materializer protectionPolicyMaterializer
	failed       error
	previews     map[string]protectionPolicyPreview
}

func newProtectionPolicyCoordinatorConsumer(h *handler.Handler, machine *controlplane.StateMachine, coordinator *controlplane.Coordinator, applier protectionPolicyMaterializer) (*protectionPolicyCoordinatorConsumer, error) {
	if h == nil || machine == nil || coordinator == nil || applier == nil {
		return nil, handler.ErrProtectionPolicyCoordinatorUnavailable
	}
	service, err := desiredstate.NewProtectionPolicyCoordinatorService(desiredstate.NewProtectionPolicyMutationService(), coordinator)
	if err != nil {
		return nil, err
	}
	return &protectionPolicyCoordinatorConsumer{
		handler: h, machine: machine, coordinator: coordinator, service: service, materializer: applier,
		previews: make(map[string]protectionPolicyPreview),
	}, nil
}

func (c *protectionPolicyCoordinatorConsumer) ProposeAndApply(ctx context.Context, actor string, patch desiredstate.ProtectionPolicyPatch) (desiredstate.ProtectionPolicyCoordinationResult, error) {
	if c == nil || !controlplane.ValidIdentity(actor) {
		return desiredstate.ProtectionPolicyCoordinationResult{}, desiredstate.ProtectionPolicyMutationValidationError{Field: "actor", Reason: "strict identity is required"}
	}
	return c.proposeAndApply(ctx, actor, patch)
}

func (c *protectionPolicyCoordinatorConsumer) Preview(ctx context.Context, actor string, patch desiredstate.ProtectionPolicyPatch) (desiredstate.ProtectionPolicyCoordinationPreview, error) {
	if c == nil || !controlplane.ValidIdentity(actor) {
		return desiredstate.ProtectionPolicyCoordinationPreview{}, desiredstate.ProtectionPolicyMutationValidationError{Field: "actor", Reason: "strict identity is required"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed != nil {
		return desiredstate.ProtectionPolicyCoordinationPreview{}, c.failed
	}
	current, err := c.handler.ConfigSnapshot(ctx)
	if err != nil {
		return desiredstate.ProtectionPolicyCoordinationPreview{}, err
	}
	state := c.machine.Snapshot()
	nonce, err := newProtectionPolicyNonce()
	if err != nil {
		return desiredstate.ProtectionPolicyCoordinationPreview{}, err
	}
	mutation, err := desiredstate.NewProtectionPolicyMutationService().Prepare(current.Protection.Policy, desiredstate.ProtectionPolicyMutationRequest{
		Actor: actor, LeaderID: state.LeaderID, ExpectedEpoch: state.Epoch, ExpectedRevision: state.Revision, Nonce: nonce, Patch: patch,
	})
	if err != nil {
		return desiredstate.ProtectionPolicyCoordinationPreview{}, err
	}
	binding, err := newProtectionPolicyNonce()
	if err != nil {
		return desiredstate.ProtectionPolicyCoordinationPreview{}, err
	}
	c.prunePreviewsLocked()
	// Store the normalized value snapshots, not the caller-owned patch. The
	// approval binding authorizes this exact Before -> After transition only.
	c.previews[binding] = protectionPolicyPreview{actor: actor, before: mutation.Before, after: mutation.After, epoch: state.Epoch, revision: state.Revision, expires: time.Now().Add(protectionPolicyPreviewTTL)}
	return desiredstate.ProtectionPolicyCoordinationPreview{Mutation: mutation, Binding: binding}, nil
}

func (c *protectionPolicyCoordinatorConsumer) ProposeAndApplyWithPreview(ctx context.Context, actor string, _ desiredstate.ProtectionPolicyPatch, binding string) (desiredstate.ProtectionPolicyCoordinationResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	preview, ok := c.previews[binding]
	if ok {
		delete(c.previews, binding)
	}
	if c.failed != nil {
		return desiredstate.ProtectionPolicyCoordinationResult{}, c.failed
	}
	if !ok || !preview.availableAt(time.Now()) || preview.actor != actor {
		return desiredstate.ProtectionPolicyCoordinationResult{}, handler.ErrProtectionPolicyCoordinatorPreviewUnavailable
	}
	return c.proposeApprovedPreviewLocked(ctx, actor, preview)
}

func (c *protectionPolicyCoordinatorConsumer) proposeAndApply(ctx context.Context, actor string, patch desiredstate.ProtectionPolicyPatch) (desiredstate.ProtectionPolicyCoordinationResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proposeAndApplyLocked(ctx, actor, patch)
}

// proposeApprovedPreviewLocked submits exactly the previewed target. The live
// handler policy and control-plane state are read only to reject a stale
// baseline or fence; caller-supplied patch pointers never participate here.
func (c *protectionPolicyCoordinatorConsumer) proposeApprovedPreviewLocked(ctx context.Context, actor string, preview protectionPolicyPreview) (desiredstate.ProtectionPolicyCoordinationResult, error) {
	if c.failed != nil {
		return desiredstate.ProtectionPolicyCoordinationResult{}, c.failed
	}
	var result desiredstate.ProtectionPolicyCoordinationResult
	err := c.handler.WithProtectionPolicyMaterialization(func() error {
		current, err := c.handler.ConfigSnapshot(ctx)
		if err != nil {
			return err
		}
		before, err := normalizeProtectionPolicy(current.Protection.Policy)
		if err != nil {
			return err
		}
		state := c.machine.Snapshot()
		if before != preview.before || state.Epoch != preview.epoch || state.Revision != preview.revision {
			return controlplane.ErrStaleRevision
		}
		nonce, err := newProtectionPolicyNonce()
		if err != nil {
			return err
		}
		proposal, err := desiredstate.NewProtectionPolicyProposal(preview.after, state.LeaderID, preview.epoch, preview.revision, nonce)
		if err != nil {
			return err
		}
		commit, err := c.coordinator.ProposeAndApply(ctx, proposal)
		result = desiredstate.ProtectionPolicyCoordinationResult{
			Mutation: desiredstate.ProtectionPolicyMutation{Actor: actor, Before: preview.before, After: preview.after, Proposal: proposal},
			Commit:   commit,
		}
		if err != nil {
			return err
		}
		materializationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), protectionPolicyMaterializationTimeout)
		defer cancel()
		return c.applyCommittedAndPublish(materializationCtx, result.Commit)
	})
	if err != nil {
		if protectionPolicyCommitStarted(result.Commit) {
			c.freezeAfterFailure(err)
		}
		return result, err
	}
	return result, nil
}

func (c *protectionPolicyCoordinatorConsumer) proposeAndApplyLocked(ctx context.Context, actor string, patch desiredstate.ProtectionPolicyPatch) (desiredstate.ProtectionPolicyCoordinationResult, error) {
	if c.failed != nil {
		return desiredstate.ProtectionPolicyCoordinationResult{}, c.failed
	}
	var result desiredstate.ProtectionPolicyCoordinationResult
	err := c.handler.WithProtectionPolicyMaterialization(func() error {
		current, err := c.handler.ConfigSnapshot(ctx)
		if err != nil {
			return err
		}
		state := c.machine.Snapshot()
		expectedEpoch := state.Epoch
		expectedRevision := state.Revision
		nonce, err := newProtectionPolicyNonce()
		if err != nil {
			return err
		}
		result, err = c.service.ProposeAndApply(ctx, current.Protection.Policy, desiredstate.ProtectionPolicyMutationRequest{
			Actor: actor, LeaderID: state.LeaderID, ExpectedEpoch: expectedEpoch, ExpectedRevision: expectedRevision, Nonce: nonce, Patch: patch,
		})
		if err != nil {
			return err
		}
		materializationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), protectionPolicyMaterializationTimeout)
		defer cancel()
		return c.applyCommittedAndPublish(materializationCtx, result.Commit)
	})
	if err != nil {
		// Validation, stale-CAS and pre-proposal cancellation errors have not
		// changed consensus, PostgreSQL, YAML or the runtime. Freezing the whole
		// generation for those caller-scoped failures would let one bad request
		// permanently deny every later policy write. Once an exact commit exists,
		// however, the local materialization boundary must remain fail-closed until
		// recovery proves that same commit end to end.
		if protectionPolicyCommitStarted(result.Commit) {
			c.freezeAfterFailure(err)
		}
		return result, err
	}
	return result, nil
}

func protectionPolicyCommitStarted(commit controlplane.Commit) bool {
	return commit.State.Revision != 0 || commit.Fence.Revision != 0
}

// applyCommittedAndPublish must run under the Handler materialization lease.
// The materializer performs YAML then runtime then journal/LKG. Only after it
// returns success may the serving snapshot advance.
func (c *protectionPolicyCoordinatorConsumer) applyCommittedAndPublish(ctx context.Context, commit controlplane.Commit) error {
	if commit.State.Desired.Version != desiredstate.Version {
		return fmt.Errorf("unsupported current desired-state version %q", commit.State.Desired.Version)
	}
	if err := c.materializer.ApplyCommitted(ctx, commit); err != nil {
		return err
	}
	current, err := c.handler.ConfigSnapshot(ctx)
	if err != nil {
		return err
	}
	candidate, err := desiredstate.MaterializeProtectionPolicy(current, commit.State.Desired.Payload)
	if err != nil {
		return err
	}
	return c.handler.PublishMaterializedConfig(ctx, candidate)
}

func (c *protectionPolicyCoordinatorConsumer) applyStartup(ctx context.Context, commit controlplane.Commit) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed != nil {
		return c.failed
	}
	materializationCtx, cancel := context.WithTimeout(ctx, protectionPolicyMaterializationTimeout)
	defer cancel()
	err := c.handler.WithProtectionPolicyMaterialization(func() error { return c.applyCommittedAndPublish(materializationCtx, commit) })
	if err != nil {
		c.freezeAfterFailure(err)
	}
	return err
}

func (c *protectionPolicyCoordinatorConsumer) freezeAfterFailure(cause error) {
	if cause == nil || c.failed != nil {
		return
	}
	c.failed = fmt.Errorf("%w: %v", errProtectionPolicyMaterializationFailed, cause)
	c.machine.FreezeWrites("protection policy materialization failed")
}

func (c *protectionPolicyCoordinatorConsumer) prunePreviewsLocked() {
	c.prunePreviewsAtLocked(time.Now())
}

func (c *protectionPolicyCoordinatorConsumer) prunePreviewsAtLocked(now time.Time) {
	for binding, preview := range c.previews {
		if !preview.availableAt(now) {
			delete(c.previews, binding)
		}
	}
}

func (p protectionPolicyPreview) availableAt(now time.Time) bool {
	return p.expires.After(now)
}

func normalizeProtectionPolicy(policy config.ProtectionPolicyConfig) (config.ProtectionPolicyConfig, error) {
	normalized := policy.WithDefaults(config.DefaultProtectionPolicy())
	if _, err := desiredstate.NewProtectionPolicyDocument(normalized); err != nil {
		return config.ProtectionPolicyConfig{}, err
	}
	return normalized, nil
}

func newProtectionPolicyNonce() (string, error) {
	var raw [24]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate protection policy nonce: %w", err)
	}
	return "pp-" + hex.EncodeToString(raw[:]), nil
}

var _ handler.ProtectionPolicyCoordinatorPreviewConsumer = (*protectionPolicyCoordinatorConsumer)(nil)
