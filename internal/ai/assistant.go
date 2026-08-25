package ai

import (
	"context"
	"fmt"
)

type Assistant struct {
	registry  *Registry
	approvals *ApprovalStore
}

type ToolExecution struct {
	Result   *ToolResult      `json:"result,omitempty"`
	Approval *ApprovalRequest `json:"approval,omitempty"`
}

func NewAssistant(registry *Registry, approvals *ApprovalStore) *Assistant {
	if registry == nil {
		registry = NewRegistry()
	}
	if approvals == nil {
		approvals = NewApprovalStore()
	}
	return &Assistant{registry: registry, approvals: approvals}
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
	if err := GuardToolAccessForActor(actor, tool, DefaultRoleToolPolicy()); err != nil {
		return nil, err
	}
	if tool.Sensitivity() != ReadOnly {
		if a.approvals == nil || !a.approvals.CanPersistModifications() {
			return nil, fmt.Errorf("approval persistence is unavailable; modification tools are disabled")
		}
		actor := ApprovalActorFromContext(ctx)
		if approvalID == "" {
			diff := ""
			preview := ""
			if previewer, ok := tool.(ToolPreviewer); ok {
				var err error
				diff, err = previewer.Preview(ctx, args)
				if err != nil {
					return nil, err
				}
				preview = diff
			}
			request, err := a.approvals.CreateForWithPreview(tool, args, diff, preview, actor)
			if err != nil {
				return nil, err
			}
			return &ToolExecution{Approval: &request}, nil
		}
		preview := ""
		if previewer, ok := tool.(ToolPreviewer); ok {
			var err error
			preview, err = previewer.Preview(ctx, args)
			if err != nil {
				return nil, err
			}
		}
		if _, err := a.approvals.BeginExecutionForWithPreview(approvalID, name, args, preview, actor); err != nil {
			return nil, fmt.Errorf("tool %q requires approved request", name)
		}
	}
	result, err := tool.Execute(ctx, args)
	if err != nil {
		if approvalID != "" {
			_, _ = a.approvals.MarkExecutionFailed(approvalID)
		}
		return nil, err
	}
	execution := &ToolExecution{Result: result}
	if approvalID != "" {
		if approval, err := a.approvals.MarkExecuted(approvalID); err == nil {
			execution.Approval = &approval
		} else {
			return nil, err
		}
	}
	return execution, nil
}

func (a *Assistant) Approve(id string) (ApprovalRequest, error) {
	return a.approvals.Approve(id)
}

func (a *Assistant) ApproveFor(id string, actor ApprovalActor) (ApprovalRequest, error) {
	return a.approvals.ApproveFor(id, actor)
}

func (a *Assistant) Reject(id string) (ApprovalRequest, error) {
	return a.approvals.Reject(id)
}

func (a *Assistant) RejectFor(id string, actor ApprovalActor) (ApprovalRequest, error) {
	return a.approvals.RejectFor(id, actor)
}
