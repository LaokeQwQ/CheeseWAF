package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

const (
	EdgeOriginRequestIDHeader    = "X-CheeseSec-Edge-Request-Id"
	EdgeOriginTimestampHeader    = "X-CheeseSec-Edge-Timestamp"
	EdgeOriginSignatureHeader    = "X-CheeseSec-Edge-Signature"
	EdgeOriginPolicyHeader       = "X-CheeseSec-Edge-Policy"
	EdgeOriginAccessIDHeader     = "CF-Access-Client-Id"
	EdgeOriginAccessSecretHeader = "CF-Access-Client-Secret"

	edgeOriginMaxSkew       = 60 * time.Second
	edgeOriginReplayTTL     = 2 * edgeOriginMaxSkew
	edgeOriginMaxReplayIDs  = 8192
	edgeOriginRequestIDSize = 128
)

type edgeOriginContextKey struct{}

// EdgeOriginOptions configures the transport trust check added by the
// Cloudflare Worker. The check never replaces user authentication or RBAC.
type EdgeOriginOptions struct {
	Secret             []byte
	AccessClientID     string
	AccessClientSecret string
	Clock              timekeeper.Clock
	ReplayTTL          time.Duration
	MaxReplayIDs       int
}

// VerifyEdgeOrigin verifies the Worker HMAC envelope when secret is present.
// An empty secret leaves the middleware disabled so local loopback operation
// remains available until the deployment explicitly enables the tunnel trust
// boundary.
func VerifyEdgeOrigin(next http.Handler, secret []byte, clock timekeeper.Clock) http.Handler {
	return VerifyEdgeOriginWithOptions(next, EdgeOriginOptions{Secret: secret, Clock: clock})
}

// VerifyEdgeOriginWithAccess is the production form that also binds the
// request to the configured Cloudflare Access service identity.
func VerifyEdgeOriginWithAccess(next http.Handler, secret []byte, accessClientID, accessClientSecret string, clock timekeeper.Clock) http.Handler {
	return VerifyEdgeOriginWithOptions(next, EdgeOriginOptions{
		Secret:             secret,
		AccessClientID:     accessClientID,
		AccessClientSecret: accessClientSecret,
		Clock:              clock,
	})
}

// VerifyEdgeOriginWithOptions is exposed for deterministic tests and launchers
// that need a bounded replay cache.
func VerifyEdgeOriginWithOptions(next http.Handler, options EdgeOriginOptions) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}
	secret := append([]byte(nil), options.Secret...)
	if len(secret) == 0 {
		return next
	}
	clock := options.Clock
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	replayTTL := options.ReplayTTL
	if replayTTL <= 0 {
		replayTTL = edgeOriginReplayTTL
	}
	maxReplayIDs := options.MaxReplayIDs
	if maxReplayIDs <= 0 {
		maxReplayIDs = edgeOriginMaxReplayIDs
	}
	verifier := &edgeOriginVerifier{
		secret:             secret,
		clock:              clock,
		accessClientID:     options.AccessClientID,
		accessClientSecret: options.AccessClientSecret,
		replayTTL:          replayTTL,
		maxReplayIDs:       maxReplayIDs,
		replayed:           make(map[string]time.Time),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			return
		}
		requestID, ok := verifier.verify(w, r)
		if !ok {
			return
		}
		cleanRequest := r.WithContext(context.WithValue(r.Context(), edgeOriginContextKey{}, requestID))
		sanitizeUntrustedForwardingHeaders(cleanRequest, verifier.accessConfigured())
		next.ServeHTTP(w, cleanRequest)
	})
}

// EdgeOriginRequestID returns the validated Worker request ID for audit or
// tracing code downstream of VerifyEdgeOrigin.
func EdgeOriginRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	value, _ := r.Context().Value(edgeOriginContextKey{}).(string)
	return value
}

type edgeOriginVerifier struct {
	secret             []byte
	clock              timekeeper.Clock
	accessClientID     string
	accessClientSecret string
	replayTTL          time.Duration
	maxReplayIDs       int

	mu       sync.Mutex
	replayed map[string]time.Time
}

func (v *edgeOriginVerifier) accessConfigured() bool {
	return v.accessClientID != "" || v.accessClientSecret != ""
}

func (v *edgeOriginVerifier) verify(w http.ResponseWriter, r *http.Request) (string, bool) {
	requestID := r.Header.Get(EdgeOriginRequestIDHeader)
	if !validEdgeOriginRequestID(requestID) {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_INVALID", "edge request id is missing or invalid")
		return "", false
	}
	timestampRaw := r.Header.Get(EdgeOriginTimestampHeader)
	if !validEdgeOriginTimestamp(timestampRaw) {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_INVALID", "edge timestamp is missing or invalid")
		return "", false
	}
	timestamp, err := strconv.ParseInt(timestampRaw, 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_INVALID", "edge timestamp is invalid")
		return "", false
	}
	now := v.clock.Now().UTC()
	if delta := now.Unix() - timestamp; delta < -int64(edgeOriginMaxSkew/time.Second) || delta > int64(edgeOriginMaxSkew/time.Second) {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_EXPIRED", "edge request timestamp is outside the allowed window")
		return "", false
	}
	signatureRaw := r.Header.Get(EdgeOriginSignatureHeader)
	signature, err := hex.DecodeString(signatureRaw)
	if err != nil || len(signature) != sha256.Size {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_INVALID", "edge signature is invalid")
		return "", false
	}
	canonical := edgeOriginCanonicalString(r, requestID, timestampRaw)
	mac := hmac.New(sha256.New, v.secret)
	_, _ = mac.Write([]byte(canonical))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_INVALID", "edge signature does not match the request")
		return "", false
	}
	if v.accessConfigured() {
		if v.accessClientID == "" || v.accessClientSecret == "" ||
			r.Header.Get(EdgeOriginAccessIDHeader) != v.accessClientID ||
			r.Header.Get(EdgeOriginAccessSecretHeader) != v.accessClientSecret {
			writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_ACCESS_INVALID", "edge Access identity is invalid")
			return "", false
		}
	}
	if edgeOriginReplayProtected(r.Method) && !v.reserve(requestID, now) {
		writeAPIError(w, http.StatusForbidden, "EDGE_ORIGIN_REPLAY", "edge request has already been used")
		return "", false
	}
	return requestID, true
}

func (v *edgeOriginVerifier) reserve(requestID string, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for id, expiresAt := range v.replayed {
		if !expiresAt.After(now) {
			delete(v.replayed, id)
		}
	}
	if _, exists := v.replayed[requestID]; exists {
		return false
	}
	if len(v.replayed) >= v.maxReplayIDs {
		var oldestID string
		var oldest time.Time
		for id, expiresAt := range v.replayed {
			if oldestID == "" || expiresAt.Before(oldest) {
				oldestID, oldest = id, expiresAt
			}
		}
		if oldestID != "" {
			delete(v.replayed, oldestID)
		}
	}
	v.replayed[requestID] = now.Add(v.replayTTL)
	return true
}

func edgeOriginCanonicalString(r *http.Request, requestID, timestamp string) string {
	path := "/"
	query := ""
	if r != nil && r.URL != nil {
		if escaped := r.URL.EscapedPath(); escaped != "" {
			path = escaped
		}
		if r.URL.RawQuery != "" {
			query = "?" + r.URL.RawQuery
		}
	}
	return strings.Join([]string{strings.ToUpper(r.Method), path, query, requestID, timestamp}, "\n")
}

func validEdgeOriginRequestID(value string) bool {
	if value == "" || len(value) > edgeOriginRequestIDSize {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}

func validEdgeOriginTimestamp(value string) bool {
	if value == "" || len(value) > 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func edgeOriginReplayProtected(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func sanitizeUntrustedForwardingHeaders(r *http.Request, accessConfigured bool) {
	if r == nil {
		return
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-forwarded-") || lower == "x-real-ip" || lower == "x-client-ip" {
			r.Header.Del(name)
			continue
		}
		if strings.HasPrefix(lower, "x-cheesesec-edge-") &&
			lower != strings.ToLower(EdgeOriginRequestIDHeader) &&
			lower != strings.ToLower(EdgeOriginTimestampHeader) &&
			lower != strings.ToLower(EdgeOriginSignatureHeader) &&
			lower != strings.ToLower(EdgeOriginPolicyHeader) {
			r.Header.Del(name)
			continue
		}
		if strings.HasPrefix(lower, "cf-access-") && !accessConfigured {
			r.Header.Del(name)
		}
	}
}
