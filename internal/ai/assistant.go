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
	if tool.Sensitivity() != ReadOnly {
		if approvalID == "" {
			request, err := a.approvals.Create(tool, args, "")
			if err != nil {
				return nil, err
			}
			return &ToolExecution{Approval: &request}, nil
		}
		request, ok := a.approvals.Get(approvalID)
		if !ok || request.ToolName != name || request.Status != ApprovalApproved {
			return nil, fmt.Errorf("tool %q requires approved request", name)
		}
	}
	result, err := tool.Execute(ctx, args)
	if err != nil {
		return nil, err
	}
	return &ToolExecution{Result: result}, nil
}

func (a *Assistant) Approve(id string) (ApprovalRequest, error) {
	return a.approvals.Approve(id)
}

func (a *Assistant) Reject(id string) (ApprovalRequest, error) {
	return a.approvals.Reject(id)
}
