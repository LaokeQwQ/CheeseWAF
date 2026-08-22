package apisec

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDiscoverPreservesStableLongAndMixedIdentifierSegments(t *testing.T) {
	now := time.Now()
	endpoints := Discover([]storage.LogEntry{
		{Timestamp: now, Method: "GET", URI: "/articles/introducing-cheesewaf", StatusCode: 200},
		{Timestamp: now, Method: "GET", URI: "/products/AB12-CD34-EF56", StatusCode: 200},
	}, config.APIDiscoveryConfig{Window: time.Hour}, now)
	if len(endpoints) != 2 {
		t.Fatalf("stable paths collapsed: %+v", endpoints)
	}
	paths := map[string]bool{}
	for _, endpoint := range endpoints {
		paths[endpoint.Path] = true
	}
	if !paths["/articles/introducing-cheesewaf"] || !paths["/products/AB12-CD34-EF56"] {
		t.Fatalf("unexpected normalized paths: %+v", paths)
	}
}

func TestDiscoverNormalizesUUIDAndRejectsInvalidStatusFamilies(t *testing.T) {
	now := time.Now()
	endpoints := Discover([]storage.LogEntry{
		{Timestamp: now, Method: "GET", URI: "/users/550e8400-e29b-41d4-a716-446655440000", StatusCode: 1200},
		{Timestamp: now, Method: "GET", URI: "/users/550e8400-e29b-41d4-a716-446655440001", StatusCode: 99},
	}, config.APIDiscoveryConfig{Window: time.Hour}, now)
	if len(endpoints) != 1 || endpoints[0].Path != "/users/{id}" {
		t.Fatalf("UUID paths did not normalize: %+v", endpoints)
	}
	if endpoints[0].StatusFamily["unknown"] != 2 || len(endpoints[0].StatusFamily) != 1 {
		t.Fatalf("invalid status codes produced a family: %+v", endpoints[0].StatusFamily)
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

func TestAuthenticatorDisabledSkipsJWKSInitialization(t *testing.T) {
	auth, err := NewAuthenticator(config.APISecConfig{
		Auth: config.APIAuthConfig{
			Enabled:        false,
			JWTAlgorithms:  []string{"HS256"},
			JWKSCacheFile:  t.TempDir() + "/missing-jwks-cache.json",
			RequiredScopes: []string{"orders:read"},
		},
	})
	if err != nil {
		t.Fatalf("disabled authenticator should not initialize JWKS verifier: %v", err)
	}
	if finding := auth.Evaluate(httptest.NewRequest(http.MethodGet, "/api/orders", nil)); finding != nil {
		t.Fatalf("disabled authenticator should not evaluate requests, got %+v", finding)
	}
}

func TestRemoteJWKSSourceCloseBeforeStartDoesNotBlock(t *testing.T) {
	source, err := newRemoteJWKSSource(config.APIAuthConfig{
		JWKSURL:     "https://keys.example.com/.well-known/jwks.json",
		JWKSRefresh: time.Hour,
	})
	if err != nil {
		t.Fatalf("remote jwks source: %v", err)
	}

	done := make(chan struct{})
	go func() {
		source.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked before remote JWKS source was started")
	}
}

func TestRemoteJWKSSourceCloseAfterStartStopsWorker(t *testing.T) {
	source, err := newRemoteJWKSSource(config.APIAuthConfig{
		JWKSURL:     "https://keys.example.com/.well-known/jwks.json",
		JWKSRefresh: time.Hour,
	})
	if err != nil {
		t.Fatalf("remote jwks source: %v", err)
	}
	source.Start()

	done := make(chan struct{})
	go func() {
		source.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked after remote JWKS source was started")
	}
}

func TestAuthenticatorEvaluatesAPIAuthClaims(t *testing.T) {
	const secret = "test-auth-secret"
	auth, err := NewAuthenticator(config.APISecConfig{
		Auth: config.APIAuthConfig{
			Enabled:         true,
			JWTAlgorithms:   []string{"HS256"},
			JWTSharedSecret: secret,
			JWTIssuers:      []string{"issuer-a"},
			RequiredScopes:  []string{"orders:read"},
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
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-a", "scope": "orders:read billing:read"}))
	if finding := auth.Evaluate(req); finding != nil {
		t.Fatalf("expected valid auth claims to pass, got %+v", finding)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", "bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-b", "scope": "orders:read"}))
	issuer := auth.Evaluate(req)
	if issuer == nil || issuer.Kind != "issuer" || issuer.Payload != "issuer-b" {
		t.Fatalf("expected issuer finding, got %+v", issuer)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-a", "scope": []string{"orders:write"}}))
	scope := auth.Evaluate(req)
	if scope == nil || scope.Kind != "scope" || scope.Payload != "orders:read" {
		t.Fatalf("expected missing scope finding, got %+v", scope)
	}

	if finding := auth.Evaluate(httptest.NewRequest(http.MethodGet, "/public", nil)); finding != nil {
		t.Fatalf("expected non-API path to bypass auth, got %+v", finding)
	}
}

func TestAuthenticatorVerifiesJWTSignatures(t *testing.T) {
	t.Run("hmac secret", func(t *testing.T) {
		auth, err := NewAuthenticator(config.APISecConfig{
			Auth: config.APIAuthConfig{
				Enabled:         true,
				JWTIssuers:      []string{"issuer-a"},
				RequiredScopes:  []string{"orders:read"},
				JWTAlgorithms:   []string{"HS256"},
				JWTSharedSecret: "test-secret",
			},
			Validation: config.APIValidationConfig{
				Schemas: []config.APIEndpointSchemaConfig{{ID: "orders", Method: http.MethodGet, PathPattern: "^/v1/orders$", Enabled: true}},
			},
		})
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", "test-secret", map[string]any{"iss": "issuer-a", "scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding != nil {
			t.Fatalf("expected valid HMAC JWT to pass, got %+v", finding)
		}

		req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", "wrong-secret", map[string]any{"iss": "issuer-a", "scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding == nil || finding.Kind != "signature" {
			t.Fatalf("expected signature finding for bad HMAC JWT, got %+v", finding)
		}

		req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestJWT(t, map[string]any{"iss": "issuer-a", "scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding == nil || finding.Kind != "signature" {
			t.Fatalf("expected signature finding for unsigned JWT, got %+v", finding)
		}
	})

	t.Run("jwks oct key", func(t *testing.T) {
		secret := []byte("jwks-secret")
		jwks := `{"keys":[{"kty":"oct","kid":"kid-1","alg":"HS256","k":"` + base64.RawURLEncoding.EncodeToString(secret) + `"}]}`
		auth, err := NewAuthenticator(config.APISecConfig{
			Auth: config.APIAuthConfig{
				Enabled:       true,
				JWTAlgorithms: []string{"HS256"},
				JWKSJSON:      jwks,
			},
			Validation: config.APIValidationConfig{
				Schemas: []config.APIEndpointSchemaConfig{{ID: "orders", Method: http.MethodGet, PathPattern: "^/v1/orders$", Enabled: true}},
			},
		})
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "kid-1", string(secret), map[string]any{"scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding != nil {
			t.Fatalf("expected JWKS HMAC JWT to pass, got %+v", finding)
		}
	})

	t.Run("rsa pem public key", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
		auth, err := NewAuthenticator(config.APISecConfig{
			Auth: config.APIAuthConfig{
				Enabled:         true,
				JWTAlgorithms:   []string{"RS256"},
				JWTPublicKeyPEM: publicPEM,
			},
			Validation: config.APIValidationConfig{
				Schemas: []config.APIEndpointSchemaConfig{{ID: "orders", Method: http.MethodGet, PathPattern: "^/v1/orders$", Enabled: true}},
			},
		})
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestRSAJWT(t, "RS256", privateKey, map[string]any{"scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding != nil {
			t.Fatalf("expected RSA JWT to pass, got %+v", finding)
		}
	})

	t.Run("remote jwks with cache fallback", func(t *testing.T) {
		secret := []byte("remote-jwks-secret")
		jwks := `{"keys":[{"kty":"oct","kid":"remote-1","alg":"HS256","k":"` + base64.RawURLEncoding.EncodeToString(secret) + `"}]}`
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(jwks))
		}))
		defer server.Close()

		oldValidator := remoteJWKSURLValidator
		oldFactory := remoteJWKSClientFactory
		remoteJWKSURLValidator = func(string) error { return nil }
		remoteJWKSClientFactory = func(time.Duration) *http.Client { return server.Client() }
		defer func() {
			remoteJWKSURLValidator = oldValidator
			remoteJWKSClientFactory = oldFactory
		}()

		cacheFile := t.TempDir() + "/jwks-cache.json"
		cfg := config.APISecConfig{
			Auth: config.APIAuthConfig{
				Enabled:        true,
				JWTAlgorithms:  []string{"HS256"},
				JWKSURL:        server.URL,
				JWKSCacheFile:  cacheFile,
				JWKSRefresh:    time.Hour,
				RequiredScopes: []string{"orders:read"},
			},
			Validation: config.APIValidationConfig{
				Schemas: []config.APIEndpointSchemaConfig{{ID: "orders", Method: http.MethodGet, PathPattern: "^/v1/orders$", Enabled: true}},
			},
		}
		auth, err := NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("authenticator: %v", err)
		}
		defer auth.Close()

		req := httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "remote-1", string(secret), map[string]any{"scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding != nil {
			t.Fatalf("expected remote JWKS JWT to pass, got %+v", finding)
		}

		req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "remote-1", "wrong-secret", map[string]any{"scope": "orders:read"}))
		if finding := auth.Evaluate(req); finding == nil || finding.Kind != "signature" {
			t.Fatalf("expected signature finding for wrong remote JWKS secret, got %+v", finding)
		}

		cached := cfg
		cached.Auth.JWKSURL = ""
		cachedAuth, err := NewAuthenticator(cached)
		if err != nil {
			t.Fatalf("cache-only authenticator: %v", err)
		}
		defer cachedAuth.Close()
		req = httptest.NewRequest(http.MethodGet, "/v1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "remote-1", string(secret), map[string]any{"scope": "orders:read"}))
		if finding := cachedAuth.Evaluate(req); finding != nil {
			t.Fatalf("expected cached JWKS JWT to pass, got %+v", finding)
		}
	})
}

func TestAuthenticatorEvaluatesAudienceAndEndpointPolicies(t *testing.T) {
	const secret = "test-auth-secret"
	auth, err := NewAuthenticator(config.APISecConfig{
		Auth: config.APIAuthConfig{
			Enabled:         true,
			JWTAlgorithms:   []string{"HS256"},
			JWTSharedSecret: secret,
			JWTIssuers:      []string{"issuer-a"},
			JWTAudiences:    []string{"orders-api"},
			RequiredScopes:  []string{"orders:read"},
			EndpointPolicies: []config.APIAuthEndpointPolicyConfig{{
				ID:             "admin-write",
				Method:         http.MethodPost,
				PathPattern:    "^/v1/admin$",
				JWTIssuers:     []string{"issuer-admin"},
				JWTAudiences:   []string{"admin-api"},
				RequiredScopes: []string{"admin:write"},
				Enabled:        true,
			}},
		},
	})
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-a", "aud": "orders-api", "scope": "orders:read"}))
	if finding := auth.Evaluate(req); finding != nil {
		t.Fatalf("expected global audience auth to pass, got %+v", finding)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/orders", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-a", "aud": "other-api", "scope": "orders:read"}))
	audience := auth.Evaluate(req)
	if audience == nil || audience.Kind != "audience" || audience.Field != "aud" {
		t.Fatalf("expected audience finding, got %+v", audience)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/admin", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-admin", "aud": []string{"admin-api"}, "scope": "admin:write"}))
	if finding := auth.Evaluate(req); finding != nil {
		t.Fatalf("expected endpoint policy auth to pass, got %+v", finding)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/admin", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-a", "aud": "orders-api", "scope": "orders:read"}))
	issuer := auth.Evaluate(req)
	if issuer == nil || issuer.Kind != "issuer" || issuer.Payload != "issuer-a" {
		t.Fatalf("expected endpoint policy issuer finding, got %+v", issuer)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/admin", nil)
	req.Header.Set("Authorization", "Bearer "+authTestHMACJWT(t, "HS256", "", secret, map[string]any{"iss": "issuer-admin", "aud": "admin-api", "scope": "admin:write"}))
	if finding := auth.Evaluate(req); finding != nil {
		t.Fatalf("expected method-mismatched endpoint policy to bypass ordinary path, got %+v", finding)
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
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

func authTestClaims(claims map[string]any) map[string]any {
	if claims == nil {
		claims = map[string]any{}
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	return claims
}

func authTestHMACJWT(t *testing.T, alg, kid, secret string, claims map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	signingInput := authTestSigningInput(t, header, authTestClaims(claims))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func authTestRSAJWT(t *testing.T, alg string, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signingInput := authTestSigningInput(t, map[string]string{"alg": alg, "typ": "JWT"}, authTestClaims(claims))
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func authTestSigningInput(t *testing.T, header map[string]string, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
}

func TestValidateWithBodySizeUsesActualBytesWhenContentLengthUnknown(t *testing.T) {
	validator, err := NewValidator(config.APIValidationConfig{
		Enabled: true,
		Schemas: []config.APIEndpointSchemaConfig{
			{ID: "upload", Method: "POST", PathPattern: `^/api/upload$`, MaxBodyBytes: 10, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.ContentLength = -1

	// Known oversized body despite chunked ContentLength.
	findings := validator.ValidateWithBodySize(req, 64)
	if len(findings) != 1 || findings[0].Field != "body" {
		t.Fatalf("expected body finding for oversized known size, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "exceeds") {
		t.Fatalf("expected exceeds message, got %+v", findings[0])
	}

	// Unknown actual size: ContentLength unknown and bodyBytes < 0 → no finding.
	findings = validator.ValidateWithBodySize(req, -1)
	if len(findings) != 0 {
		t.Fatalf("expected no finding when body size is unknown, got %+v", findings)
	}

	// ContentLength still consulted when bodyBytes is unknown.
	reqKnown := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	reqKnown.ContentLength = 64
	findings = validator.ValidateWithBodySize(reqKnown, -1)
	if len(findings) != 1 || findings[0].Field != "body" {
		t.Fatalf("expected ContentLength fallback finding, got %+v", findings)
	}
}

func TestValidateWithBodySizeRequiredParamsStillWork(t *testing.T) {
	validator, err := NewValidator(config.APIValidationConfig{
		Enabled: true,
		Schemas: []config.APIEndpointSchemaConfig{
			{ID: "search", Method: "GET", PathPattern: `^/api/search$`, RequiredParams: []string{"q", "page"}, Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	// Multiple required params: query is parsed once for the request path.
	findings := validator.ValidateWithBodySize(httptest.NewRequest(http.MethodGet, "/api/search?page=1", nil), -1)
	if len(findings) != 1 || findings[0].Field != "q" {
		t.Fatalf("expected missing q finding only, got %+v", findings)
	}
	findings = validator.ValidateWithBodySize(httptest.NewRequest(http.MethodGet, "/api/search?q=hi&page=2", nil), -1)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when required params present, got %+v", findings)
	}
	// Validate keeps working for existing callers.
	findings = validator.Validate(httptest.NewRequest(http.MethodGet, "/api/search", nil))
	if len(findings) != 2 {
		t.Fatalf("expected two missing-param findings via Validate, got %+v", findings)
	}
}

func TestJWTVerifyRequiresKidWhenMultipleCandidateKeys(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{
		"keys": []map[string]any{
			rsaPublicJWK(t, "key-a", &key1.PublicKey),
			rsaPublicJWK(t, "key-b", &key2.PublicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newJWTVerifier(config.APIAuthConfig{
		JWTAlgorithms: []string{"RS256"},
		JWKSJSON:      string(jwks),
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	// Token signed with key1 but no kid — must not brute-force across candidates.
	tokenStr := authTestRSAJWT(t, "RS256", key1, map[string]any{"scope": "orders:read"})
	parsed, err := parseJWT(tokenStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.kid != "" {
		t.Fatalf("test token must omit kid, got %q", parsed.kid)
	}
	err = verifier.Verify(parsed)
	if err == nil {
		t.Fatal("expected verification to fail when kid is missing and multiple keys match")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "kid") {
		t.Fatalf("expected kid-required error, got %v", err)
	}

	// Same token with correct kid succeeds against the matching key only.
	tokenWithKid := authTestRSAJWTWithKid(t, "RS256", "key-a", key1, map[string]any{"scope": "orders:read"})
	parsed, err = parseJWT(tokenWithKid)
	if err != nil {
		t.Fatalf("parse with kid: %v", err)
	}
	if err := verifier.Verify(parsed); err != nil {
		t.Fatalf("expected kid-selected key to verify, got %v", err)
	}
}

func TestJWTVerifyRejectsGarbageKidWhenKeysHaveNoKid(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{
		"keys": []map[string]any{
			rsaPublicJWK(t, "", &key1.PublicKey),
			rsaPublicJWK(t, "", &key2.PublicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := newJWTVerifier(config.APIAuthConfig{
		JWTAlgorithms: []string{"RS256"},
		JWKSJSON:      string(jwks),
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	tokenStr := authTestRSAJWTWithKid(t, "RS256", "garbage", key1, map[string]any{"scope": "orders:read"})
	parsed, err := parseJWT(tokenStr)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.kid != "garbage" {
		t.Fatalf("expected garbage kid, got %q", parsed.kid)
	}
	err = verifier.Verify(parsed)
	if err == nil {
		t.Fatal("expected verification to fail; empty-kid keys must not be wildcards under a token kid")
	}
}

func authTestRSAJWTWithKid(t *testing.T, alg, kid string, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signingInput := authTestSigningInput(t, map[string]string{"alg": alg, "typ": "JWT", "kid": kid}, authTestClaims(claims))
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func rsaPublicJWK(t *testing.T, kid string, pub *rsa.PublicKey) map[string]any {
	t.Helper()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}
