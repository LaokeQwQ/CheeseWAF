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

func TestRBACProviderReadsPermissionsForEveryRequest(t *testing.T) {
	claims := &Claims{Role: "operator"}
	permissions := PermissionMap{"operator": []string{"read:logs"}}
	called := 0
	handler := RBACProvider(func() PermissionMap { return permissions }, "write:sites")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called++
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(context.WithValue(request.Context(), UserContextKey, claims))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request)
	if first.Code != http.StatusForbidden {
		t.Fatalf("initial status = %d, want 403", first.Code)
	}

	permissions = PermissionMap{"operator": []string{"write:sites"}}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request)
	if second.Code != http.StatusOK || called != 1 {
		t.Fatalf("updated status = %d, calls = %d", second.Code, called)
	}
}
