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
)

type contextKey string

const UserContextKey contextKey = "user"

type TokenManager struct {
	secret []byte
	ttl    time.Duration
}

type Claims struct {
	Subject  string   `json:"sub"`
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
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := time.Now().UTC()
	claims := Claims{Subject: subject, Username: username, Role: role, Scopes: []string{role}, IssuedAt: now.Unix(), Expires: now.Add(m.ttl).Unix()}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	unsigned := encode(headerJSON) + "." + encode(claimsJSON)
	sig := m.sign(unsigned)
	return unsigned + "." + sig, nil
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

func (m *TokenManager) sign(unsigned string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(unsigned))
	return encode(mac.Sum(nil))
}

func encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"unauthorized"}}`))
}
