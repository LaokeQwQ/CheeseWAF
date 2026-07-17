package middleware

import "testing"

func TestAllowedUsesRolePermissions(t *testing.T) {
	claims := &Claims{Role: "operator"}
	if !allowed(claims, PermissionMap{"operator": []string{"read:*"}}, "read:logs") {
		t.Fatal("expected read permission")
	}
	if allowed(claims, PermissionMap{"operator": []string{"read:*"}}, "write:sites") {
		t.Fatal("did not expect write permission")
	}
}
