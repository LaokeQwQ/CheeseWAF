package ai

import (
	"context"
	"fmt"
)

type Assistant struct {
	registry     *Registry
	approvals    *ApprovalStore
	gateApproval *GateApprovalAdapter
}

type ToolExecution struct {
	Result   *ToolResult      `json:"result,omitempty"`
	Approval *ApprovalRequest `json:"approval,omitempty"`
}

func NewAssistant(registry *Registry, approvals *ApprovalStore) *Assistant {
	return NewAssistantWithApprovalGate(registry, approvals, nil)
}

// NewAssistantWithApprovalGate keeps the historical constructor intact while
// allowing callers to opt destructive tools into the strict core approval
// gate. Modify tools continue using ApprovalStore's compatibility path.
func NewAssistantWithApprovalGate(registry *Registry, approvals *ApprovalStore, gateApproval *GateApprovalAdapter) *Assistant {
	if registry == nil {
		registry = NewRegistry()
	}
	if approvals == nil && gateApproval != nil {
		approvals = gateApproval.Store()
	}
	if approvals == nil {
		approvals = NewApprovalStore()
	}
	if gateApproval != nil && gateApproval.Store() != approvals {
		gateApproval = nil
	}
	return &Assistant{registry: registry, approvals: approvals, gateApproval: gateApproval}
}

// NewAssistantWithGateApproval is a naming alias for callers that phrase the
// dependency as a gate rather than an adapter.
func NewAssistantWithGateApproval(registry *Registry, approvals *ApprovalStore, gateApproval *GateApprovalAdapter) *Assistant {
	return NewAssistantWithApprovalGate(registry, approvals, gateApproval)
}

func (a *Assistant) ExecuteTool(ctx context.Context, name string, args map[string]any, approvalID string) (*ToolExecution, error) {
	if a == nil || a.registry == nil {
		return nil, fmt.Errorf("assistant is not initialized")
	}
	tool, ok := a.registry.Get(name)
	if !ok {
		return nil, fmt.Errorf("tool %q not found", name)
	}
	// R3: role-based tool whitelist (does not weaken dual-control approvals).
	actor := ApprovalActorFromContext(ctx)
	if dynamic, ok := tool.(interface {
		SensitivityForArgs(map[string]any) ToolSensitivity
	}); ok {
		tool = argumentSensitivityTool{Tool: tool, sensitivity: dynamic.SensitivityForArgs(args)}
	}
	if err := GuardToolAccessForActor(actor, tool, DefaultRoleToolPolicy()); err != nil {
		return nil, err
	}
	executionCtx := ctx
	if tool.Sensitivity() != ReadOnly {
		if a.approvals == nil || !a.approvals.CanPersistModifications() {
			return nil, fmt.Errorf("approval persistence is unavailable; modification tools are disabled")
		}
		actor := ApprovalActorFromContext(ctx)
		if tool.Sensitivity() == Destructive {
			if a.gateApproval == nil {
				return nil, ErrHighRiskApprovalUnavailable
			}
			if approvalID == "" {
				diff, preview, err := previewForTool(ctx, tool, args)
				if err != nil {
					return nil, err
				}
				request, err := a.gateApproval.CreateForWithPreview(tool, args, diff, preview, actor)
				if err != nil {
					return nil, err
				}
				return &ToolExecution{Approval: &request}, nil
			}
			preview, err := a.executionPreview(ctx, tool, args, approvalID)
			if err != nil {
				return nil, err
			}
			if _, err := a.gateApproval.BeginExecutionForWithPreview(approvalID, name, args, preview, actor); err != nil {
				return nil, fmt.Errorf("tool %q requires gate-backed approved request: %w", name, err)
			}
			executionCtx = ContextWithToolPreviewBinding(ctx, preview)
		} else {
			if approvalID == "" {
				diff, preview, err := previewForTool(ctx, tool, args)
				if err != nil {
					return nil, err
				}
				request, err := a.approvals.CreateForWithPreview(tool, args, diff, preview, actor)
				if err != nil {
					return nil, err
				}
				return &ToolExecution{Approval: &request}, nil
			}
			preview, err := a.executionPreview(ctx, tool, args, approvalID)
			if err != nil {
				return nil, err
			}
			if _, err := a.approvals.BeginExecutionForWithPreview(approvalID, name, args, preview, actor); err != nil {
				return nil, fmt.Errorf("tool %q requires approved request: %w", name, err)
			}
			executionCtx = ContextWithToolPreviewBinding(ctx, preview)
		}
	} else {
		// Read-only tools never create approval requests, so an approval id
		// carried on a read-only call can only belong to another request.
		// Drop it: honouring the id would let any caller finalize (and thereby
		// destroy) somebody else's in-flight modification out from under its
		// owner. MarkExecuted/MarkExecutionFailed now reject a foreign
		// requester too, but that is the backstop, not the licence to pass
		// ids around.
		approvalID = ""
	}
	result, err := tool.Execute(executionCtx, args)
	if err != nil {
		if approvalID != "" {
			if tool.Sensitivity() == Destructive && a.gateApproval != nil {
				_, _ = a.gateApproval.MarkExecutionFailed(approvalID, actor)
			} else {
				_, _ = a.approvals.MarkExecutionFailed(approvalID, actor)
			}
		}
		return nil, err
	}
	execution := &ToolExecution{Result: result}
	if approvalID != "" {
		var approval ApprovalRequest
		var markErr error
		if tool.Sensitivity() == Destructive && a.gateApproval != nil {
			approval, markErr = a.gateApproval.MarkExecuted(approvalID, actor)
		} else {
			approval, markErr = a.approvals.MarkExecuted(approvalID, actor)
		}
		if markErr == nil {
			execution.Approval = &approval
		} else {
			return nil, markErr
		}
	}
	return execution, nil
}

func (a *Assistant) executionPreview(ctx context.Context, tool Tool, args map[string]any, id string) (string, error) {
	if bound, ok := tool.(interface{ UsesStoredPreviewBinding() bool }); ok && bound.UsesStoredPreviewBinding() {
		request, exists := a.approvals.Get(id)
		if !exists || request.PreviewBinding == "" {
			return "", fmt.Errorf("approved preview binding is unavailable")
		}
		return request.PreviewBinding, nil
	}
	_, binding, err := previewForTool(ctx, tool, args)
	return binding, err
}

func previewForTool(ctx context.Context, tool Tool, args map[string]any) (diff, binding string, err error) {
	if resolver, ok := tool.(ToolPreviewResolver); ok {
		diff, binding, err = resolver.ResolvePreview(ctx, args)
		if err != nil {
			return "", "", err
		}
		if binding == "" {
			binding = diff
		}
		return diff, binding, nil
	}
	if previewer, ok := tool.(ToolPreviewer); ok {
		diff, err = previewer.Preview(ctx, args)
		return diff, diff, err
	}
	return "", "", nil
}

func (a *Assistant) Approve(id string) (ApprovalRequest, error) {
	return a.approvals.Approve(id)
}

func (a *Assistant) ApproveFor(id string, actor ApprovalActor) (ApprovalRequest, error) {
	return a.approvals.ApproveFor(id, actor)
}

// BeginApprovalConfirmation starts the strict high-risk warning window.
func (a *Assistant) BeginApprovalConfirmation(id string, actor ApprovalActor, language string) (GateApprovalChallenge, error) {
	if a == nil || a.gateApproval == nil {
		return GateApprovalChallenge{}, ErrHighRiskApprovalUnavailable
	}
	return a.gateApproval.BeginConfirmation(id, actor, language)
}

// ConfirmApprovalFor is the explicit high-risk confirmation entry point.
func (a *Assistant) ConfirmApprovalFor(id string, actor ApprovalActor, input GateApprovalConfirmation) (GateApprovalResult, error) {
	if a == nil || a.gateApproval == nil {
		return GateApprovalResult{}, ErrHighRiskApprovalUnavailable
	}
	return a.gateApproval.Confirm(id, actor, input)
}

func (a *Assistant) Reject(id string) (ApprovalRequest, error) {
	return a.approvals.Reject(id)
}

func (a *Assistant) RejectFor(id string, actor ApprovalActor) (ApprovalRequest, error) {
	if approval, ok := a.approvals.Get(id); ok && approval.Sensitivity == Destructive && a.gateApproval != nil {
		return a.gateApproval.RejectFor(id, actor, "AI high-risk approval rejected")
	}
	return a.approvals.RejectFor(id, actor)
}

type argumentSensitivityTool struct {
	Tool
	sensitivity ToolSensitivity
}

func (t argumentSensitivityTool) Sensitivity() ToolSensitivity { return t.sensitivity }
func (t argumentSensitivityTool) RequiredPermission() string {
	if scoped, ok := t.Tool.(ToolPermissioner); ok {
		return scoped.RequiredPermission()
	}
	return ""
}
func (t argumentSensitivityTool) UsesStoredPreviewBinding() bool {
	bound, ok := t.Tool.(interface{ UsesStoredPreviewBinding() bool })
	return ok && bound.UsesStoredPreviewBinding()
}
func (t argumentSensitivityTool) ResolvePreview(ctx context.Context, args map[string]any) (string, string, error) {
	return previewForTool(ctx, t.Tool, args)
}
