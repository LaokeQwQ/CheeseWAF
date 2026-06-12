package middleware

import (
	"net/http"
	"strings"
)

type PermissionMap map[string][]string

func RBAC(permissions PermissionMap, required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := r.Context().Value(UserContextKey).(*Claims)
			if claims == nil {
				writeUnauthorized(w)
				return
			}
			if allowed(claims, permissions, required) {
				next.ServeHTTP(w, r)
				return
			}
			writeAPIError(w, http.StatusForbidden, "FORBIDDEN", "permission denied")
		})
	}
}

func allowed(claims *Claims, permissions PermissionMap, required string) bool {
	if claims.Role == "admin" {
		return true
	}
	for _, scope := range claims.Scopes {
		if matchesPermission(scope, required) {
			return true
		}
	}
	for _, permission := range permissions[claims.Role] {
		if matchesPermission(permission, required) {
			return true
		}
	}
	return false
}

func matchesPermission(permission, required string) bool {
	if permission == "*" || permission == required {
		return true
	}
	if strings.HasSuffix(permission, "*") {
		return strings.HasPrefix(required, strings.TrimSuffix(permission, "*"))
	}
	return false
}
