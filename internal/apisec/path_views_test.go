package apisec

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestAPIAuthRequiresTokenAcrossSecurityPathViews(t *testing.T) {
	auth, err := NewAuthenticator(config.APISecConfig{Auth: config.APIAuthConfig{
		Enabled: true, JWTAlgorithms: []string{"HS256"}, JWTSharedSecret: "path-view-secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	for _, target := range []string{"/api/private", "//api/private", "/public/../api/private", "/%2561pi/private", "/api;v=1/private"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.test"+target, nil)
			before := req.URL.RequestURI()
			if got := auth.Evaluate(req); got == nil || got.Kind != "missing" {
				t.Fatalf("protected path did not require a token: %+v", got)
			}
			if req.URL.RequestURI() != before {
				t.Fatal("authentication changed the transport path")
			}
		})
	}
	if got := auth.Evaluate(httptest.NewRequest(http.MethodGet, "/public", nil)); got != nil {
		t.Fatalf("ordinary non-API path gained an auth requirement: %+v", got)
	}
}

func TestAPIAuthEnforcesEveryPathViewRequirement(t *testing.T) {
	const secret = "path-view-secret"
	auth, err := NewAuthenticator(config.APISecConfig{Auth: config.APIAuthConfig{
		Enabled: true, JWTAlgorithms: []string{"HS256"}, JWTSharedSecret: secret,
		EndpointPolicies: []config.APIAuthEndpointPolicyConfig{
			{ID: "raw", Enabled: true, Method: http.MethodPost, PathPattern: `^/api;v=1/admin$`, RequiredScopes: []string{"legacy:read"}, JWTIssuers: []string{"shared", "raw-only"}, JWTAudiences: []string{"raw-audience"}},
			{ID: "canonical", Enabled: true, Method: http.MethodPost, PathPattern: `^/api/admin$`, RequiredScopes: []string{"admin:write"}, JWTIssuers: []string{"shared", "canonical-only"}, JWTAudiences: []string{"canonical-audience"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	for _, tc := range []struct {
		name, issuer, scope, wantKind string
		audiences                     []string
	}{
		{"raw scope cannot weaken canonical", "shared", "legacy:read", "scope", []string{"raw-audience", "canonical-audience"}},
		{"canonical scope cannot weaken raw", "shared", "admin:write", "scope", []string{"raw-audience", "canonical-audience"}},
		{"raw issuer cannot weaken canonical", "raw-only", "legacy:read admin:write", "issuer", []string{"raw-audience", "canonical-audience"}},
		{"raw audience cannot weaken canonical", "shared", "legacy:read admin:write", "audience", []string{"raw-audience"}},
		{"all requirements pass", "shared", "legacy:read admin:write", "", []string{"raw-audience", "canonical-audience"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api;v=1/admin", nil)
			req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": tc.issuer, "aud": tc.audiences, "scope": tc.scope}))
			got := auth.Evaluate(req)
			if tc.wantKind == "" {
				if got != nil {
					t.Fatalf("valid token rejected: %+v", got)
				}
			} else if got == nil || got.Kind != tc.wantKind {
				t.Fatalf("finding=%+v, want %s", got, tc.wantKind)
			}
		})
	}
}

func TestAPIAuthKeepsEndpointSpecificityWithinEachPathView(t *testing.T) {
	const secret = "path-view-secret"
	auth, err := NewAuthenticator(config.APISecConfig{Auth: config.APIAuthConfig{
		Enabled: true, JWTAlgorithms: []string{"HS256"}, JWTSharedSecret: secret,
		RequiredScopes: []string{"global:scope"},
		EndpointPolicies: []config.APIAuthEndpointPolicyConfig{
			{ID: "broad", Enabled: true, PathPattern: `^/api/`, RequiredScopes: []string{"broad:scope"}},
			{ID: "narrow", Enabled: true, PathPattern: `^/api/private$`, RequiredScopes: []string{"private:scope"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	req := httptest.NewRequest(http.MethodGet, "/api/private", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"scope": "private:scope"}))
	if got := auth.Evaluate(req); got != nil {
		t.Fatalf("endpoint override/specificity changed: %+v", got)
	}
}

func TestAPIAuthMatchesConfiguredNonAPISecurityPaths(t *testing.T) {
	for _, source := range []string{"schema", "rate"} {
		t.Run(source, func(t *testing.T) {
			cfg := config.APISecConfig{Auth: config.APIAuthConfig{
				Enabled: true, JWTAlgorithms: []string{"HS256"}, JWTSharedSecret: "path-view-secret",
			}}
			if source == "schema" {
				cfg.Validation.Schemas = []config.APIEndpointSchemaConfig{{ID: "protected", Enabled: true, Method: http.MethodPost, PathPattern: `^/protected$`}}
			} else {
				cfg.RateLimits = []config.APIEndpointLimitConfig{{ID: "protected", Enabled: true, Method: http.MethodPost, PathPattern: `^/protected$`, Requests: 1, Window: time.Minute}}
			}
			auth, err := NewAuthenticator(cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = auth.Close() })
			if got := auth.Evaluate(httptest.NewRequest(http.MethodPost, "https://example.test//protected", nil)); got == nil || got.Kind != "missing" {
				t.Fatalf("configured non-API path did not require token: %+v", got)
			}
			if got := auth.Evaluate(httptest.NewRequest(http.MethodGet, "https://example.test//protected", nil)); got != nil {
				t.Fatalf("method mismatch acquired a requirement: %+v", got)
			}
		})
	}
}

func TestAPISecurityRejectsInvalidPathWithoutMutatingRequest(t *testing.T) {
	auth, err := NewAuthenticator(config.APISecConfig{Auth: config.APIAuthConfig{
		Enabled: true, JWTAlgorithms: []string{"HS256"}, JWTSharedSecret: "path-view-secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	validator, err := NewValidator(config.APIValidationConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewRateLimiter(nil)
	if err != nil {
		t.Fatal(err)
	}
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/..;/private", nil),
		{Method: http.MethodGet, Header: make(http.Header)},
	}
	for _, req := range requests {
		if got := auth.Evaluate(req); got == nil || got.Kind != "invalid" || got.Field != "path" {
			t.Fatalf("invalid path did not fail auth closed: %+v", got)
		}
		if got := validator.Validate(req); len(got) != 1 || got[0].Field != "path" {
			t.Fatalf("invalid path did not fail schema closed: %+v", got)
		}
		if limiter.Allow(req, "client") {
			t.Fatal("invalid path passed rate limiter")
		}
	}
	if got := auth.Evaluate(nil); got != nil {
		t.Fatalf("nil auth request behavior changed: %+v", got)
	}
	if got := validator.Validate(nil); got != nil {
		t.Fatalf("nil schema request behavior changed: %+v", got)
	}
	if !limiter.Allow(nil, "client") {
		t.Fatal("nil rate request behavior changed")
	}
}

func TestAPISchemaMatchesSecurityPathViewsOncePerSchema(t *testing.T) {
	validator, err := NewValidator(config.APIValidationConfig{Enabled: true, Schemas: []config.APIEndpointSchemaConfig{
		{ID: "canonical", Enabled: true, Method: http.MethodGet, PathPattern: `^/api/private$`, RequiredParams: []string{"q"}},
		{ID: "raw", Enabled: true, Method: http.MethodGet, PathPattern: `^/api;v=1/private$`, RequiredHeaders: []string{"X-Legacy"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"//api/private", "/api/x/../private", "/api/%252e/private"} {
		t.Run(target, func(t *testing.T) {
			got := validator.Validate(httptest.NewRequest(http.MethodGet, "https://example.test"+target, nil))
			if len(got) != 1 || got[0].SchemaID != "canonical" || got[0].Field != "q" {
				t.Fatalf("canonical schema skipped or duplicated: %+v", got)
			}
		})
	}
	got := validator.Validate(httptest.NewRequest(http.MethodGet, "/api;v=1/private", nil))
	if len(got) != 2 || got[0].SchemaID != "canonical" || got[1].SchemaID != "raw" {
		t.Fatalf("raw/canonical schema requirements not both retained: %+v", got)
	}
	if got := validator.Validate(httptest.NewRequest(http.MethodPost, "//api/private", nil)); len(got) != 0 {
		t.Fatalf("schema method filtering changed: %+v", got)
	}
}

func TestAPIEndpointRateLimitMatchesSecurityPathViewsOnce(t *testing.T) {
	for _, target := range []string{"//api/private", "/api/x/../private", "/api/%252e/private", "/api;v=1/private"} {
		t.Run(target, func(t *testing.T) {
			limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{ID: "api", Enabled: true, Method: http.MethodGet, PathPattern: `^/api/private$`, Requests: 2, Window: time.Minute}})
			if err != nil {
				t.Fatal(err)
			}
			requests := []*http.Request{
				httptest.NewRequest(http.MethodGet, "https://example.test"+target, nil),
				httptest.NewRequest(http.MethodGet, "/api/private", nil),
			}
			for n, want := range []bool{true, true, false} {
				if got := limiter.AllowRequests(requests[:1], "client"); got != want {
					t.Fatalf("request %d allowed=%v, want %v", n+1, got, want)
				}
			}
			secondClient := "both-identities"
			if !limiter.AllowRequests(requests, secondClient) || !limiter.AllowRequests(requests, secondClient) || limiter.AllowRequests(requests, secondClient) {
				t.Fatal("multiple identities charged a matching rule more than once")
			}
		})
	}
	limiter, err := NewRateLimiter([]config.APIEndpointLimitConfig{{ID: "raw", Enabled: true, PathPattern: `^/legacy;v=1/`, Requests: 1, Window: time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	raw := httptest.NewRequest(http.MethodGet, "/legacy;v=1/private", nil)
	if !limiter.Allow(raw, "client") || limiter.Allow(raw, "client") {
		t.Fatal("raw legacy endpoint expression stopped matching")
	}
}
