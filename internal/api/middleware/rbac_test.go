package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedUsesRolePermissions(t *testing.T) {
	claims := &Claims{Role: "operator"}
	if !allowed(claims, PermissionMap{"operator": []string{"read:*"}}, "read:logs") {
		t.Fatal("expected read permission")
	}
	if allowed(claims, PermissionMap{"operator": []string{"read:*"}}, "write:sites") {
		t.Fatal("did not expect write permission")
	}
}

func TestRBACAnyAcceptsOneMatchingPermission(t *testing.T) {
	claims := &Claims{Role: "writer"}
	permissions := PermissionMap{"writer": []string{"write:ai"}}
	called := false
	handler := RBACAny(permissions, "read:ai", "write:ai", "approve:ai")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(context.WithValue(request.Context(), UserContextKey, claims))
	handler.ServeHTTP(httptest.NewRecorder(), request)
	if !called {
		t.Fatal("RBACAny rejected a caller with one matching permission")
	}
}
