package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
)

type contextKey string

const UserContextKey contextKey = "user"

type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

type Claims struct {
	Subject  string   `json:"sub"`
	ID       string   `json:"jti,omitempty"`
	Username string   `json:"username"`
	Role     string   `json:"role"`
	Scopes   []string `json:"scope"`
	IssuedAt int64    `json:"iat"`
	Expires  int64    `json:"exp"`
}

func NewTokenManager(secret string, ttl time.Duration) *TokenManager {
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err == nil {
			secret = base64.RawURLEncoding.EncodeToString(buf)
		} else {
			secret = fmt.Sprintf("cheesewaf-ephemeral-%d", time.Now().UnixNano())
		}
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenManager{secret: []byte(secret), ttl: ttl}
}

func (m *TokenManager) Sign(subject, username, role string) (string, error) {
	token, _, err := m.SignWithClaims(subject, username, role)
	return token, err
}

func (m *TokenManager) SignWithClaims(subject, username, role string) (string, *Claims, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := time.Now().UTC()
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
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	unsigned := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(m.sign(unsigned))) {
		return nil, fmt.Errorf("invalid token signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if time.Now().UTC().Unix() > claims.Expires {
		return nil, fmt.Errorf("token expired")
	}
	return &claims, nil
}

func (m *TokenManager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if token == "" || token == header {
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

type SessionValidator interface {
	IsSessionActive(ctx context.Context, id, userID string, now time.Time) (bool, error)
}

func SessionMiddleware(validator SessionValidator) func(http.Handler) http.Handler {
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
			active, err := validator.IsSessionActive(r.Context(), claims.ID, claims.Subject, time.Now().UTC())
			if err != nil || !active {
				writeUnauthorized(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":     code,
			"message":  message,
			"trace_id": traceID,
		},
	})
}
