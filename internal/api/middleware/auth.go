package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const UserContextKey contextKey = "user"

const ManagementAPITokenPrefix = "cwapi_"

type TokenManager struct {
	secret []byte
	ttl    time.Duration
	ready  bool
	now    func() time.Time
}

var readTokenManagerSecret = rand.Read

type Claims struct {
	Subject   string   `json:"sub"`
	ID        string   `json:"jti,omitempty"`
	Username  string   `json:"username"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scope"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	Expires   int64    `json:"exp"`
}

func NewTokenManager(secret string, ttl time.Duration) *TokenManager {
	return NewTokenManagerWithClock(secret, ttl, timekeeper.SystemClock{})
}

func NewTokenManagerWithClock(secret string, ttl time.Duration, clock timekeeper.Clock) *TokenManager {
	ready := true
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := readTokenManagerSecret(buf); err == nil {
			secret = base64.RawURLEncoding.EncodeToString(buf)
		} else {
			ready = false
		}
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenManager{secret: []byte(secret), ttl: ttl, ready: ready && secret != "", now: utcNowFunc(clock)}
}

func (m *TokenManager) Sign(subject, username, role string) (string, error) {
	token, _, err := m.SignWithClaims(subject, username, role)
	return token, err
}

func (m *TokenManager) SignWithClaims(subject, username, role string) (string, *Claims, error) {
	if m == nil || !m.ready || len(m.secret) == 0 {
		return "", nil, fmt.Errorf("token manager signing secret is unavailable")
	}
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := m.nowUTC()
	tokenID, err := randomTokenID()
	if err != nil {
		return "", nil, err
	}
	claims := Claims{Subject: subject, ID: tokenID, Username: username, Role: role, Scopes: []string{role}, IssuedAt: now.Unix(), Expires: now.Add(m.ttl).Unix()}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", nil, err
	}
	unsigned := encode(headerJSON) + "." + encode(claimsJSON)
	sig := m.sign(unsigned)
	return unsigned + "." + sig, &claims, nil
}

func (m *TokenManager) Verify(token string) (*Claims, error) {
	if m == nil || !m.ready || len(m.secret) == 0 {
		return nil, fmt.Errorf("token manager signing secret is unavailable")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	unsigned := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(m.sign(unsigned))) {
		return nil, fmt.Errorf("invalid token signature")
	}
	headerPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerPayload, &header); err != nil || header.Algorithm != "HS256" || (header.Type != "" && header.Type != "JWT") {
		return nil, fmt.Errorf("invalid token header")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	now := m.nowUTC().Unix()
	if claims.Expires <= 0 || now >= claims.Expires {
		return nil, fmt.Errorf("token expired")
	}
	if claims.IssuedAt <= 0 || claims.IssuedAt > now+30 {
		return nil, fmt.Errorf("token issued at invalid time")
	}
	if claims.NotBefore > now+30 {
		return nil, fmt.Errorf("token not active")
	}
	if claims.Expires <= claims.IssuedAt {
		return nil, fmt.Errorf("token lifetime is invalid")
	}
	return &claims, nil
}

func (m *TokenManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prefer HttpOnly session cookie; fall back to Authorization Bearer.
		token := SessionToken(r)
		if token == "" {
			writeUnauthorized(w)
			return
		}
		if strings.HasPrefix(token, ManagementAPITokenPrefix) {
			// Management API tokens are not browser session JWTs.
			writeUnauthorized(w)
			return
		}
		claims, err := m.Verify(token)
		if err != nil {
			writeUnauthorized(w)
			return
		}
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ManagementAPITokenAuthenticator may return an after-request callback for
// throttled bookkeeping that must run outside authentication/configuration
// locks. The middleware runs it even when the downstream handler panics.
type ManagementAPITokenAuthenticator func(raw string, at time.Time) (*Claims, func(), bool)

func ManagementAPIOrSessionMiddleware(manager *TokenManager, validator SessionValidator, authenticate ManagementAPITokenAuthenticator) func(http.Handler) http.Handler {
	return ManagementAPIOrSessionMiddlewareWithClock(manager, validator, authenticate, timekeeper.SystemClock{})
}

func ManagementAPIOrSessionMiddlewareWithClock(manager *TokenManager, validator SessionValidator, authenticate ManagementAPITokenAuthenticator, clock timekeeper.Clock) func(http.Handler) http.Handler {
	now := utcNowFunc(clock)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Management API tokens only via Authorization Bearer (never from cookie).
			if raw := bearerToken(r); strings.HasPrefix(raw, ManagementAPITokenPrefix) {
				if authenticate == nil {
					writeUnauthorized(w)
					return
				}
				claims, afterRequest, ok := authenticate(raw, now())
				if !ok {
					writeUnauthorized(w)
					return
				}
				if afterRequest != nil {
					defer afterRequest()
				}
				ctx := context.WithValue(r.Context(), UserContextKey, claims)
				// Keep the authenticated context on the request pointer as well as
				// passing it downstream. The audit middleware may wrap this middleware
				// and inspect the original request after the handler returns.
				*r = *r.WithContext(ctx)
				next.ServeHTTP(w, r)
				return
			}

			token := SessionToken(r)
			if token == "" {
				writeUnauthorized(w)
				return
			}
			if manager == nil || validator == nil {
				writeUnauthorized(w)
				return
			}
			claims, err := manager.Verify(token)
			if err != nil {
				writeUnauthorized(w)
				return
			}
			active, err := validator.IsSessionActive(r.Context(), claims.ID, claims.Subject, now())
			if err != nil || !active {
				writeUnauthorized(w)
				return
			}
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			*r = *r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func HashManagementAPIToken(raw string) string {
	// Management tokens contain 256 random bits, so a fast one-way digest does
	// not reduce offline resistance. It avoids exposing every unauthenticated API
	// request to password-hash CPU cost. bcrypt remains accepted for migration.
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashManagementAPITokenLegacySHA256 is used only for tests that need deterministic digests.
func HashManagementAPITokenLegacySHA256(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func managementAPITokenMatches(raw, stored string) bool {
	raw = strings.TrimSpace(raw)
	stored = strings.TrimSpace(stored)
	if raw == "" || stored == "" {
		return false
	}
	switch {
	case strings.HasPrefix(stored, "bcrypt:"):
		return bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(stored, "bcrypt:")), []byte(raw)) == nil
	case strings.HasPrefix(stored, "sha256:"):
		// Accept legacy SHA-256 hashes until operators re-create tokens.
		sum := sha256.Sum256([]byte(raw))
		want := "sha256:" + hex.EncodeToString(sum[:])
		return hmac.Equal([]byte(want), []byte(stored))
	default:
		return false
	}
}

func VerifyManagementAPIToken(raw string, cfg config.ManagementAPIConfig, now time.Time) (*Claims, bool) {
	if !cfg.Enabled || strings.TrimSpace(raw) == "" {
		return nil, false
	}
	now = now.UTC()
	for _, token := range cfg.Tokens {
		if !token.Enabled || token.ID == "" || token.Hash == "" || !token.RevokedAt.IsZero() {
			continue
		}
		if !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(now) {
			continue
		}
		// Prefixes are public lookup keys generated with each token. Filtering
		// before hash verification keeps legacy bcrypt compatibility without an
		// attacker forcing one bcrypt operation per configured token.
		prefix := strings.TrimSpace(token.Prefix)
		if prefix == "" || !strings.HasPrefix(raw, prefix) {
			continue
		}
		if !managementAPITokenMatches(raw, token.Hash) {
			continue
		}
		expires := int64(0)
		if !token.ExpiresAt.IsZero() {
			expires = token.ExpiresAt.Unix()
		}
		issuedAt := token.CreatedAt
		if issuedAt.IsZero() {
			issuedAt = now
		}
		name := strings.TrimSpace(token.Name)
		if name == "" {
			name = token.ID
		}
		return &Claims{
			Subject:  "api-token:" + token.ID,
			ID:       token.ID,
			Username: name,
			Role:     "api_token",
			Scopes:   append([]string(nil), token.Scopes...),
			IssuedAt: issuedAt.Unix(),
			Expires:  expires,
		}, true
	}
	return nil, false
}

type SessionValidator interface {
	IsSessionActive(ctx context.Context, id, userID string, now time.Time) (bool, error)
}

func SessionMiddleware(validator SessionValidator) func(http.Handler) http.Handler {
	return SessionMiddlewareWithClock(validator, timekeeper.SystemClock{})
}

func SessionMiddlewareWithClock(validator SessionValidator, clock timekeeper.Clock) func(http.Handler) http.Handler {
	now := utcNowFunc(clock)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validator == nil {
				writeUnauthorized(w)
				return
			}
			claims, _ := r.Context().Value(UserContextKey).(*Claims)
			if claims == nil || claims.ID == "" || claims.Subject == "" {
				writeUnauthorized(w)
				return
			}
			active, err := validator.IsSessionActive(r.Context(), claims.ID, claims.Subject, now())
			if err != nil || !active {
				writeUnauthorized(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *TokenManager) nowUTC() time.Time {
	if m == nil || m.now == nil {
		return timekeeper.SystemClock{}.Now().UTC()
	}
	return m.now()
}

func utcNowFunc(clock timekeeper.Clock) func() time.Time {
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	return func() time.Time {
		return clock.Now().UTC()
	}
}

func bearerToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (m *TokenManager) sign(unsigned string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(unsigned))
	return encode(mac.Sum(nil))
}

func encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func randomTokenID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func writeUnauthorized(w http.ResponseWriter) {
	writeAPIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unauthorized")
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	traceID := blockpage.NewTraceID()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-CheeseWAF-Trace-ID", traceID)
	w.Header().Set("X-CheeseWAF-Event-ID", traceID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":     code,
			"message":  message,
			"trace_id": traceID,
			"event_id": traceID,
		},
	})
}
