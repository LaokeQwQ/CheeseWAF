package ai

import (
	"context"
	"testing"
)

type roleProbeTool struct {
	name string
	sens ToolSensitivity
}

func (t roleProbeTool) Name() string                 { return t.name }
func (t roleProbeTool) Description() string          { return t.name }
func (t roleProbeTool) Sensitivity() ToolSensitivity { return t.sens }
func (t roleProbeTool) Parameters() map[string]any   { return map[string]any{} }
func (t roleProbeTool) Execute(context.Context, map[string]any) (*ToolResult, error) {
	return &ToolResult{Success: true}, nil
}

func TestRoleToolPolicyReadOnlyDefault(t *testing.T) {
	p := DefaultRoleToolPolicy()
	tool := roleProbeTool{name: "recent_security_events", sens: ReadOnly}
	if !p.ToolAllowed("readonly", tool) {
		t.Fatal("readonly should run read-only tools")
	}
	mod := roleProbeTool{name: "set_bot_challenge", sens: Modify}
	if p.ToolAllowed("readonly", mod) {
		t.Fatal("readonly must not run modify tools")
	}
	if !p.ToolAllowed("operator", mod) {
		t.Fatal("operator should run allow-listed modify tools")
	}
	if err := GuardToolAccess("readonly", mod, p); err == nil {
		t.Fatal("expected guard error")
	}
}

func TestRoleToolPolicyUnknownAndEmptyRolesAreReadOnly(t *testing.T) {
	p := DefaultRoleToolPolicy()
	read := roleProbeTool{name: "read", sens: ReadOnly}
	modify := roleProbeTool{name: "modify", sens: Modify}
	for _, role := range []string{"", "typo-role"} {
		if !p.ToolAllowed(role, read) {
			t.Fatalf("role %q should retain read-only access", role)
		}
		if p.ToolAllowed(role, modify) {
			t.Fatalf("role %q must not inherit modification access", role)
		}
	}
}
