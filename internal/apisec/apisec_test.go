package apisec

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

func TestDiscoverNormalizesVariablePaths(t *testing.T) {
	endpoints := Discover([]storage.LogEntry{
		{Timestamp: time.Now(), Method: "GET", URI: "/api/users/123?expand=1", StatusCode: 200},
		{Timestamp: time.Now(), Method: "GET", URI: "/api/users/456", StatusCode: 403, Action: "block"},
	}, config.APIDiscoveryConfig{Window: time.Hour}, time.Now())
	if len(endpoints) != 1 || endpoints[0].Path != "/api/users/{id}" || endpoints[0].Blocked != 1 {
		t.Fatalf("unexpected endpoints: %+v", endpoints)
	}
}

func TestValidatorReportsMissingQueryParam(t *testing.T) {
	validator, err := NewValidator(config.APIValidationConfig{
		Enabled: true,
		Schemas: []config.APIEndpointSchemaConfig{
			{ID: "search", Method: "GET", PathPattern: `^/api/search$`, RequiredParams: []string{"q"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	findings := validator.Validate(httptest.NewRequest(http.MethodGet, "/api/search", nil))
	if len(findings) != 1 || findings[0].Field != "q" {
		t.Fatalf("expected missing q finding, got %+v", findings)
	}
}

func TestAuthenticatorEvaluatesAPIAuthClaims(t *testing.T) {
	auth, err := NewAuthenticator(config.APISecConfig{
		Auth: config.APIAuthConfig{
			Enabled:        true,
			JWTIssuers:     []string{"issuer-a"},
			RequiredScopes: []string{"orders:read"},
		},
		Validation: config.APIValidationConfig{
			Schemas: []config.APIEndpointSchemaConfig{{
				ID: "orders", Method: http.MethodGet, PathPattern: "^/v1/orders$", Enabled: true,
			}},
		},
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	missing := auth.Evaluate(httptest.NewRequest(http.MethodGet, "/v1/orders", nil))
	if missing == nil || missing.Kind != "missing" {
		t.Fatalf("expected missing auth finding, got %+v", missing)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", "Bearer "+authTestJWT(t, map[string]any{"iss": "issuer-a", "scope": "orders:read billing:read"}))
	if finding := auth.Evaluate(req); finding != nil {
		t.Fatalf("expected valid auth claims to pass, got %+v", finding)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", "bearer "+authTestJWT(t, map[string]any{"iss": "issuer-b", "scope": "orders:read"}))
	issuer := auth.Evaluate(req)
	if issuer == nil || issuer.Kind != "issuer" || issuer.Payload != "issuer-b" {
		t.Fatalf("expected issuer finding, got %+v", issuer)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", "Bearer "+authTestJWT(t, map[string]any{"iss": "issuer-a", "scope": []string{"orders:write"}}))
	scope := auth.Evaluate(req)
	if scope == nil || scope.Kind != "scope" || scope.Payload != "orders:read" {
		t.Fatalf("expected missing scope finding, got %+v", scope)
	}

	if finding := auth.Evaluate(httptest.NewRequest(http.MethodGet, "/public", nil)); finding != nil {
		t.Fatalf("expected non-API path to bypass auth, got %+v", finding)
	}
}

func authTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}
