package approval

// AuthorityResolver decides whether a canonical management role may use the
// approval boundary. It is deliberately separate from the Gate so callers
// must provide the policy that turns a stored role into an approval authority.
type AuthorityResolver interface {
	CanApprove(role, scope string) bool
	CanBreakGlass(role, scope string) bool
}

// DefaultAuthorityResolver is the production-safe fallback. The built-in
// admin role can perform ordinary approvals, but it never becomes emergency
// authority without an explicit resolver.
type DefaultAuthorityResolver struct{}

func (DefaultAuthorityResolver) CanApprove(role, _ string) bool {
	return role == "admin"
}

func (DefaultAuthorityResolver) CanBreakGlass(string, string) bool {
	return false
}

// CanonicalActorRole maps exact persisted management role names to Gate actor
// roles. Unknown and custom role names are not approval authorities.
func CanonicalActorRole(role string) (ActorRole, bool) {
	switch role {
	case "admin":
		return RoleOperator, true
	case string(RoleSecurityAdmin):
		return RoleSecurityAdmin, true
	case string(RoleTenantOwner):
		return RoleTenantOwner, true
	default:
		return "", false
	}
}
