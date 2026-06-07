package apisec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type Authenticator struct {
	enabled        bool
	issuers        map[string]struct{}
	requiredScopes []string
	matchers       []endpointMatcher
	now            func() time.Time
}

type endpointMatcher struct {
	method  string
	pattern *regexp.Regexp
}

type AuthFinding struct {
	Kind     string `json:"kind"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Payload  string `json:"payload,omitempty"`
}

func NewAuthenticator(cfg config.APISecConfig) (*Authenticator, error) {
	auth := &Authenticator{
		enabled:        cfg.Auth.Enabled,
		issuers:        map[string]struct{}{},
		requiredScopes: append([]string(nil), cfg.Auth.RequiredScopes...),
		now:            time.Now,
	}
	for _, issuer := range cfg.Auth.JWTIssuers {
		issuer = strings.TrimSpace(issuer)
		if issuer != "" {
			auth.issuers[issuer] = struct{}{}
		}
	}
	for _, item := range cfg.Validation.Schemas {
		if !item.Enabled {
			continue
		}
		matcher, err := newEndpointMatcher(item.Method, item.PathPattern)
		if err != nil {
			return nil, err
		}
		auth.matchers = append(auth.matchers, matcher)
	}
	for _, item := range cfg.RateLimits {
		if !item.Enabled {
			continue
		}
		matcher, err := newEndpointMatcher(item.Method, item.PathPattern)
		if err != nil {
			return nil, err
		}
		auth.matchers = append(auth.matchers, matcher)
	}
	return auth, nil
}

func newEndpointMatcher(method, pathPattern string) (endpointMatcher, error) {
	pattern, err := regexp.Compile(pathPattern)
	if err != nil {
		return endpointMatcher{}, err
	}
	return endpointMatcher{method: method, pattern: pattern}, nil
}

func (a *Authenticator) Evaluate(r *http.Request) *AuthFinding {
	if a == nil || !a.enabled || r == nil || !a.applies(r) {
		return nil
	}
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return &AuthFinding{Kind: "missing", Field: "authorization", Message: "API authorization token is missing", Severity: "medium"}
	}
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return &AuthFinding{Kind: "invalid", Field: "authorization", Message: "API authorization scheme is invalid", Severity: "high"}
	}
	claims, err := parseJWTClaims(fields[1])
	if err != nil {
		return &AuthFinding{Kind: "invalid", Field: "authorization", Message: "API authorization token is invalid", Severity: "high", Payload: err.Error()}
	}
	if expires, ok := numericClaim(claims["exp"]); ok && expires > 0 && int64(expires) < a.now().Unix() {
		return &AuthFinding{Kind: "invalid", Field: "exp", Message: "API authorization token is expired", Severity: "high"}
	}
	if len(a.issuers) > 0 {
		issuer, _ := stringClaim(claims["iss"])
		if _, ok := a.issuers[issuer]; !ok {
			return &AuthFinding{Kind: "issuer", Field: "iss", Message: "API authorization issuer is not allowed", Severity: "medium", Payload: issuer}
		}
	}
	if len(a.requiredScopes) > 0 {
		scopes := scopeClaims(claims)
		for _, required := range a.requiredScopes {
			if _, ok := scopes[required]; !ok {
				return &AuthFinding{Kind: "scope", Field: "scope", Message: "API authorization scope is missing", Severity: "medium", Payload: required}
			}
		}
	}
	return nil
}

func (a *Authenticator) applies(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") || path == "/api" {
		return true
	}
	for _, matcher := range a.matchers {
		if matcher.method != "" && !strings.EqualFold(matcher.method, r.Method) {
			continue
		}
		if matcher.pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func parseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT segment count")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func stringClaim(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok
}

func numericClaim(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int64:
		return float64(typed), true
	case int:
		return float64(typed), true
	default:
		return 0, false
	}
}

func scopeClaims(claims map[string]any) map[string]struct{} {
	scopes := map[string]struct{}{}
	add := func(value any) {
		switch typed := value.(type) {
		case string:
			for _, scope := range strings.Fields(typed) {
				scopes[scope] = struct{}{}
			}
		case []any:
			for _, item := range typed {
				if scope, ok := item.(string); ok && scope != "" {
					scopes[scope] = struct{}{}
				}
			}
		case []string:
			for _, scope := range typed {
				if scope != "" {
					scopes[scope] = struct{}{}
				}
			}
		}
	}
	add(claims["scope"])
	add(claims["scp"])
	return scopes
}
