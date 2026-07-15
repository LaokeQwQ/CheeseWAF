package apisec

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

type Authenticator struct {
	enabled        bool
	issuers        map[string]struct{}
	audiences      map[string]struct{}
	requiredScopes []string
	matchers       []endpointMatcher
	endpoints      []authEndpointPolicy
	verifier       *jwtVerifier
	now            func() time.Time
}

type authRequirement struct {
	issuers        map[string]struct{}
	audiences      map[string]struct{}
	requiredScopes []string
}

type endpointMatcher struct {
	method  string
	pattern *regexp.Regexp
}

type authEndpointPolicy struct {
	id             string
	method         string
	pattern        *regexp.Regexp
	issuers        map[string]struct{}
	audiences      map[string]struct{}
	requiredScopes []string
}

type AuthFinding struct {
	Kind     string `json:"kind"`
	Field    string `json:"field"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Payload  string `json:"payload,omitempty"`
}

func NewAuthenticator(cfg config.APISecConfig) (*Authenticator, error) {
	return NewAuthenticatorWithClock(cfg, timekeeper.SystemClock{})
}

func NewAuthenticatorWithClock(cfg config.APISecConfig, clock timekeeper.Clock) (*Authenticator, error) {
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	auth := &Authenticator{
		enabled:        cfg.Auth.Enabled,
		issuers:        map[string]struct{}{},
		audiences:      map[string]struct{}{},
		requiredScopes: append([]string(nil), cfg.Auth.RequiredScopes...),
		now:            clock.Now,
	}
	if cfg.Auth.Enabled {
		verifier, err := newJWTVerifier(cfg.Auth)
		if err != nil {
			return nil, err
		}
		auth.verifier = verifier
	}
	for _, issuer := range cfg.Auth.JWTIssuers {
		issuer = strings.TrimSpace(issuer)
		if issuer != "" {
			auth.issuers[issuer] = struct{}{}
		}
	}
	for _, audience := range cfg.Auth.JWTAudiences {
		audience = strings.TrimSpace(audience)
		if audience != "" {
			auth.audiences[audience] = struct{}{}
		}
	}
	for _, item := range cfg.Auth.EndpointPolicies {
		if !item.Enabled {
			continue
		}
		policy, err := newAuthEndpointPolicy(item)
		if err != nil {
			return nil, err
		}
		auth.endpoints = append(auth.endpoints, policy)
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

func (a *Authenticator) Close() error {
	if a != nil && a.verifier != nil {
		a.verifier.Close()
	}
	return nil
}

func newEndpointMatcher(method, pathPattern string) (endpointMatcher, error) {
	pattern, err := regexp.Compile(pathPattern)
	if err != nil {
		return endpointMatcher{}, err
	}
	return endpointMatcher{method: method, pattern: pattern}, nil
}

func newAuthEndpointPolicy(cfg config.APIAuthEndpointPolicyConfig) (authEndpointPolicy, error) {
	matcher, err := newEndpointMatcher(cfg.Method, cfg.PathPattern)
	if err != nil {
		return authEndpointPolicy{}, err
	}
	return authEndpointPolicy{
		id:             cfg.ID,
		method:         matcher.method,
		pattern:        matcher.pattern,
		issuers:        stringSet(cfg.JWTIssuers),
		audiences:      stringSet(cfg.JWTAudiences),
		requiredScopes: compactStrings(cfg.RequiredScopes),
	}, nil
}

func (a *Authenticator) Evaluate(r *http.Request) *AuthFinding {
	if a == nil || !a.enabled || r == nil {
		return nil
	}
	requirement, applies := a.requirementFor(r)
	if !applies {
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
	token, err := parseJWT(fields[1])
	if err != nil {
		return &AuthFinding{Kind: "invalid", Field: "authorization", Message: "API authorization token is invalid", Severity: "high", Payload: err.Error()}
	}
	// Fail closed: enabled API auth must always verify signatures.
	if a.verifier == nil || !a.verifier.configured() {
		return &AuthFinding{Kind: "signature", Field: "authorization", Message: "API authorization verifier is not configured", Severity: "high"}
	}
	if err := a.verifier.Verify(token); err != nil {
		return &AuthFinding{Kind: "signature", Field: "authorization", Message: "API authorization token signature is invalid", Severity: "high", Payload: err.Error()}
	}
	claims := token.claims
	expires, hasExp := numericClaim(claims["exp"])
	if !hasExp || expires <= 0 {
		return &AuthFinding{Kind: "invalid", Field: "exp", Message: "API authorization token is missing exp", Severity: "high"}
	}
	if int64(expires) <= a.now().Unix() {
		return &AuthFinding{Kind: "invalid", Field: "exp", Message: "API authorization token is expired", Severity: "high"}
	}
	if len(requirement.issuers) > 0 {
		issuer, _ := stringClaim(claims["iss"])
		if _, ok := requirement.issuers[issuer]; !ok {
			return &AuthFinding{Kind: "issuer", Field: "iss", Message: "API authorization issuer is not allowed", Severity: "medium", Payload: issuer}
		}
	}
	if len(requirement.audiences) > 0 {
		audiences := audienceClaims(claims)
		if !setsIntersect(audiences, requirement.audiences) {
			return &AuthFinding{Kind: "audience", Field: "aud", Message: "API authorization audience is not allowed", Severity: "medium", Payload: strings.Join(setKeys(audiences), ",")}
		}
	}
	if len(requirement.requiredScopes) > 0 {
		scopes := scopeClaims(claims)
		for _, required := range requirement.requiredScopes {
			if _, ok := scopes[required]; !ok {
				return &AuthFinding{Kind: "scope", Field: "scope", Message: "API authorization scope is missing", Severity: "medium", Payload: required}
			}
		}
	}
	return nil
}

func (a *Authenticator) requirementFor(r *http.Request) (authRequirement, bool) {
	for _, endpoint := range a.endpoints {
		if endpoint.matches(r) {
			return authRequirement{
				issuers:        firstSet(endpoint.issuers, a.issuers),
				audiences:      firstSet(endpoint.audiences, a.audiences),
				requiredScopes: firstList(endpoint.requiredScopes, a.requiredScopes),
			}, true
		}
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") || path == "/api" {
		return a.globalRequirement(), true
	}
	for _, matcher := range a.matchers {
		if matcher.method != "" && !strings.EqualFold(matcher.method, r.Method) {
			continue
		}
		if matcher.pattern.MatchString(path) {
			return a.globalRequirement(), true
		}
	}
	return authRequirement{}, false
}

func (a *Authenticator) globalRequirement() authRequirement {
	return authRequirement{
		issuers:        a.issuers,
		audiences:      a.audiences,
		requiredScopes: a.requiredScopes,
	}
}

func (p authEndpointPolicy) matches(r *http.Request) bool {
	if p.method != "" && !strings.EqualFold(p.method, r.Method) {
		return false
	}
	return p.pattern != nil && p.pattern.MatchString(r.URL.Path)
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

func audienceClaims(claims map[string]any) map[string]struct{} {
	audiences := map[string]struct{}{}
	add := func(value any) {
		switch typed := value.(type) {
		case string:
			if typed != "" {
				audiences[typed] = struct{}{}
			}
		case []any:
			for _, item := range typed {
				if audience, ok := item.(string); ok && audience != "" {
					audiences[audience] = struct{}{}
				}
			}
		case []string:
			for _, audience := range typed {
				if audience != "" {
					audiences[audience] = struct{}{}
				}
			}
		}
	}
	add(claims["aud"])
	return audiences
}

func stringSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return set
}

func compactStrings(values []string) []string {
	var compact []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			compact = append(compact, value)
		}
	}
	return compact
}

func firstSet(primary, fallback map[string]struct{}) map[string]struct{} {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func firstList(primary, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func setsIntersect(left, right map[string]struct{}) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}

func setKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	return keys
}
