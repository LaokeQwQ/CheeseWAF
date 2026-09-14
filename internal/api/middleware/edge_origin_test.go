package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type edgeOriginTestClock struct{ now time.Time }

func (c edgeOriginTestClock) Now() time.Time { return c.now }

func signEdgeOrigin(secret []byte, method, path, query, requestID, timestamp string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = io.WriteString(mac, strings.Join([]string{method, path, query, requestID, timestamp}, "\n"))
	return hex.EncodeToString(mac.Sum(nil))
}

func edgeOriginRequest(method, target, requestID, timestamp string, secret []byte) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(`{"name":"demo"}`))
	url := req.URL
	query := ""
	if url.RawQuery != "" {
		query = "?" + url.RawQuery
	}
	req.Header.Set(EdgeOriginRequestIDHeader, requestID)
	req.Header.Set(EdgeOriginTimestampHeader, timestamp)
	req.Header.Set(EdgeOriginSignatureHeader, signEdgeOrigin(secret, method, url.EscapedPath(), query, requestID, timestamp))
	return req
}

func TestVerifyEdgeOriginAcceptsValidEnvelopeAndCleansForwardingHeaders(t *testing.T) {
	secret := []byte("edge-secret")
	now := time.Unix(1_800_000_000, 0).UTC()
	var got *http.Request
	handler := VerifyEdgeOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		w.WriteHeader(http.StatusNoContent)
	}), secret, edgeOriginTestClock{now: now})

	req := edgeOriginRequest(http.MethodPost, "https://api.cheesesec.com/api/sites?cursor=1", "req-1", "1800000000", secret)
	req.Header.Set("X-Forwarded-For", "198.51.100.8")
	req.Header.Set("X-Real-IP", "198.51.100.8")
	req.Header.Set("X-CheeseSec-Edge-Fake", "spoofed")
	req.Header.Set("CF-Access-Client-Id", "spoofed")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", recorder.Code, http.StatusNoContent)
	}
	if got == nil {
		t.Fatal("downstream handler did not receive the request")
	}
	if got.Header.Get("X-Forwarded-For") != "" || got.Header.Get("X-Real-IP") != "" {
		t.Fatalf("forwarding headers were not removed: %+v", got.Header)
	}
	if got.Header.Get("X-CheeseSec-Edge-Fake") != "" || got.Header.Get("CF-Access-Client-Id") != "" {
		t.Fatalf("spoofable headers were not removed: %+v", got.Header)
	}
	if EdgeOriginRequestID(got) != "req-1" {
		t.Fatalf("request id=%q, want req-1", EdgeOriginRequestID(got))
	}
}

func TestVerifyEdgeOriginRejectsMissingExpiredAndAlteredEnvelopes(t *testing.T) {
	secret := []byte("edge-secret")
	now := time.Unix(1_800_000_000, 0).UTC()
	handler := VerifyEdgeOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), secret, edgeOriginTestClock{now: now})

	tests := []struct {
		name    string
		request *http.Request
		code    string
	}{
		{
			name:    "missing request id",
			request: edgeOriginRequest(http.MethodGet, "https://api.cheesesec.com/health/ready", "req-2", "1800000000", secret),
			code:    "EDGE_ORIGIN_INVALID",
		},
		{
			name:    "expired timestamp",
			request: edgeOriginRequest(http.MethodGet, "https://api.cheesesec.com/health/ready", "req-3", "1799990000", secret),
			code:    "EDGE_ORIGIN_EXPIRED",
		},
		{
			name:    "altered path",
			request: edgeOriginRequest(http.MethodGet, "https://api.cheesesec.com/health/ready", "req-4", "1800000000", secret),
			code:    "EDGE_ORIGIN_INVALID",
		},
	}
	tests[0].request.Header.Del(EdgeOriginRequestIDHeader)
	tests[2].request.URL.Path = "/health/cluster"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, tc.request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d, want %d", recorder.Code, http.StatusForbidden)
			}
			body, _ := io.ReadAll(recorder.Result().Body)
			if !strings.Contains(string(body), tc.code) {
				t.Fatalf("body=%s, want code %s", body, tc.code)
			}
		})
	}
}

func TestVerifyEdgeOriginBindsAccessIdentityAndRejectsReplay(t *testing.T) {
	secret := []byte("edge-secret")
	now := time.Unix(1_800_000_000, 0).UTC()
	var calls int
	handler := VerifyEdgeOriginWithOptions(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}), EdgeOriginOptions{
		Secret:             secret,
		AccessClientID:     "access-id",
		AccessClientSecret: "access-secret",
		Clock:              edgeOriginTestClock{now: now},
		MaxReplayIDs:       4,
	})

	valid := edgeOriginRequest(http.MethodPost, "https://api.cheesesec.com/api/sites", "req-5", "1800000000", secret)
	valid.Header.Set(EdgeOriginAccessIDHeader, "access-id")
	valid.Header.Set(EdgeOriginAccessSecretHeader, "access-secret")
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, valid)
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status=%d, want %d", first.Code, http.StatusNoContent)
	}
	replay := valid.Clone(valid.Context())
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, replay)
	if second.Code != http.StatusForbidden || !strings.Contains(second.Body.String(), "EDGE_ORIGIN_REPLAY") {
		t.Fatalf("replay response=%d %s, want forbidden replay", second.Code, second.Body.String())
	}
	if calls != 1 {
		t.Fatalf("downstream calls=%d, want 1", calls)
	}

	invalidAccess := edgeOriginRequest(http.MethodGet, "https://api.cheesesec.com/health/ready", "req-6", "1800000000", secret)
	invalidAccess.Header.Set(EdgeOriginAccessIDHeader, "wrong")
	invalidAccess.Header.Set(EdgeOriginAccessSecretHeader, "access-secret")
	third := httptest.NewRecorder()
	handler.ServeHTTP(third, invalidAccess)
	if third.Code != http.StatusForbidden || !strings.Contains(third.Body.String(), "EDGE_ORIGIN_ACCESS_INVALID") {
		t.Fatalf("invalid Access response=%d %s", third.Code, third.Body.String())
	}
}

func TestVerifyEdgeOriginDoesNotBypassNormalAuthentication(t *testing.T) {
	secret := []byte("edge-secret")
	now := time.Unix(1_800_000_000, 0).UTC()
	handler := VerifyEdgeOrigin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeUnauthorized(w)
	}), secret, edgeOriginTestClock{now: now})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, edgeOriginRequest(http.MethodGet, "https://api.cheesesec.com/api/sites", "req-7", "1800000000", secret))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want normal auth status %d", recorder.Code, http.StatusUnauthorized)
	}
}
