package cli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type serviceEdgeClock struct{ now time.Time }

func (c serviceEdgeClock) Now() time.Time { return c.now }

func serviceEdgeSignature(secret, method, path, requestID, timestamp string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strings.Join([]string{method, path, "", requestID, timestamp}, "\n")))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestEdgeOriginProtectedAdminHandlerUsesEnvironmentTrust(t *testing.T) {
	t.Setenv(edgeOriginHMACEnv, "edge-secret")
	t.Setenv(cloudflareAccessIDEnv, "access-id")
	t.Setenv(cloudflareAccessSecretEnv, "access-secret")
	clock := serviceEdgeClock{now: time.Unix(1_800_000_000, 0).UTC()}
	handler, err := edgeOriginProtectedAdminHandler(
		&config.Config{},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if middleware.EdgeOriginRequestID(r) != "service-req" {
				t.Errorf("request id=%q, want service-req", middleware.EdgeOriginRequestID(r))
			}
			w.WriteHeader(http.StatusNoContent)
		}),
		"admin-secret",
		clock,
	)
	if err != nil {
		t.Fatalf("edge origin handler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.cheesesec.com/health/ready", nil)
	req.Header.Set(middleware.EdgeOriginRequestIDHeader, "service-req")
	req.Header.Set(middleware.EdgeOriginTimestampHeader, "1800000000")
	req.Header.Set(middleware.EdgeOriginSignatureHeader, serviceEdgeSignature("edge-secret", http.MethodGet, "/health/ready", "service-req", "1800000000"))
	req.Header.Set(middleware.EdgeOriginAccessIDHeader, "access-id")
	req.Header.Set(middleware.EdgeOriginAccessSecretHeader, "access-secret")
	req.Header.Set("X-Forwarded-For", "198.51.100.12")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", recorder.Code, http.StatusNoContent)
	}
}

func TestEdgeOriginProtectedAdminHandlerRejectsPartialEnvironment(t *testing.T) {
	t.Setenv(edgeOriginHMACEnv, "")
	t.Setenv(cloudflareAccessIDEnv, "access-id")
	t.Setenv(cloudflareAccessSecretEnv, "")
	if _, err := edgeOriginProtectedAdminHandler(&config.Config{}, http.NotFoundHandler(), "admin-secret", serviceEdgeClock{}); err == nil {
		t.Fatal("partial Access configuration should fail before serving")
	}
}
