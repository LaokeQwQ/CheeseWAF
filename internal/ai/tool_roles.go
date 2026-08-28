package ai

import (
	"fmt"
	"strings"
)

// RoleToolPolicy is the R3 whitelist of tools allowed per console role.
// Roles not listed fall back to read-only tools only.
type RoleToolPolicy struct {
	// AllowedTools maps role -> set of tool names. Empty set with AllowReadOnly
	// means all ReadOnly tools plus any listed names for higher sensitivity.
	AllowedTools map[string]map[string]struct{}
	// AllowReadOnly grants every ReadOnly tool when true (default).
	AllowReadOnly bool
	// MaxSensitivity caps tools for a role (default: Modify for admin, ReadOnly for readonly).
	MaxSensitivity map[string]ToolSensitivity
}

// DefaultRoleToolPolicy is the locked dual-control friendly default.
func DefaultRoleToolPolicy() RoleToolPolicy {
	return RoleToolPolicy{
		AllowReadOnly: true,
		MaxSensitivity: map[string]ToolSensitivity{
			"admin":     Destructive,
			"operator":  Modify,
			"readonly":  ReadOnly,
			"api_token": ReadOnly,
		},
		AllowedTools: map[string]map[string]struct{}{
			// Explicit allow-list for modification tools (admin/operator).
			"admin": {
				"set_bot_challenge":    {},
				"set_protection_level": {},
				"set_ip_access":        {},
				"set_rate_limit":       {},
			},
			"operator": {
				"set_bot_challenge":    {},
				"set_protection_level": {},
			},
		},
	}
}

// ToolAllowed reports whether role may invoke tool (by name + sensitivity).
func (p RoleToolPolicy) ToolAllowed(role string, tool Tool) bool {
	if tool == nil {
		return false
	}
	role = strings.ToLower(strings.TrimSpace(role))
	sens := tool.Sensitivity()
	max, ok := p.MaxSensitivity[role]
	if !ok {
		// Unknown roles must never gain write access through a typo or a new
		// role that was added without an explicit AI policy entry.
		max = ReadOnly
	}
	if sens > max {
		return false
	}
	if sens == ReadOnly && p.AllowReadOnly {
		return true
	}
	// Admin: all tools under the administrator sensitivity cap.
	if role == "admin" {
		return true
	}
	allowed := p.AllowedTools[role]
	if allowed == nil {
		// Named non-admin roles without an allow-list: only ReadOnly (already handled).
		// Custom roles with max>=Modify may use any non-destructive tool under their cap.
		return sens <= max && max >= Modify
	}
	_, ok = allowed[tool.Name()]
	return ok
}

// GuardToolAccess returns an error if the actor role cannot use the tool.
func GuardToolAccess(role string, tool Tool, policy RoleToolPolicy) error {
	return GuardToolAccessForActor(ApprovalActor{Role: role}, tool, policy)
}

// GuardToolAccessForActor applies both the role sensitivity ceiling and any
// tool-specific permission requirement declared by the tool.
func GuardToolAccessForActor(actor ApprovalActor, tool Tool, policy RoleToolPolicy) error {
	if tool == nil {
		return fmt.Errorf("tool is nil")
	}
	role := strings.ToLower(strings.TrimSpace(actor.Role))
	if !policy.ToolAllowed(role, tool) {
		return fmt.Errorf("tool %q is not allowed for role %q", tool.Name(), actor.Role)
	}
	if permissioner, ok := tool.(ToolPermissioner); ok {
		required := strings.TrimSpace(permissioner.RequiredPermission())
		if required != "" && !permissionAllowedForActor(actor, required) {
			return fmt.Errorf("tool %q requires permission %q", tool.Name(), required)
		}
	}
	return nil
}

func permissionAllowedForActor(actor ApprovalActor, required string) bool {
	if strings.EqualFold(strings.TrimSpace(actor.Role), "admin") {
		return true
	}
	for _, permission := range actor.Permissions {
		permission = strings.TrimSpace(permission)
		if permission == "*" || permission == required {
			return true
		}
		if strings.HasSuffix(permission, "*") && strings.HasPrefix(required, strings.TrimSuffix(permission, "*")) {
			return true
		}
	}
	return false
}
