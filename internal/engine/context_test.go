package engine

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestNewRequestContextRejectsBodyOverHardLimit(t *testing.T) {
	body := strings.Repeat("a", defaultRequestBodyLimit) + "tail"
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", io.NopCloser(bytes.NewBufferString(body)))

	if _, err := NewRequestContext(req, "site-a"); !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("expected ErrRequestBodyTooLarge, got %v", err)
	}
}

func TestNewRequestContextWithLimitsRejectsChunkedBodyOverHardLimit(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", io.NopCloser(strings.NewReader("123456789")))
	req.ContentLength = -1
	if _, err := NewRequestContextWithLimits(req, "site-a", nil, 8); !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("expected chunked body to exceed hard limit, got %v", err)
	}
}

func TestNewRequestContextWithLimitsReplaysFullyInspectedBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("12345678"))
	ctx, err := NewRequestContextWithLimits(req, "site-a", nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(ctx.DecodedBody); got != "12345678" {
		t.Fatalf("decoded body = %q", got)
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil || string(replayed) != "12345678" {
		t.Fatalf("replayed body = %q, err=%v", replayed, err)
	}
}

func TestNewRequestContextReservesDetectionResults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx, err := NewRequestContextDeferredBody(req, "site-a", nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	if cap(ctx.Results) < 8 {
		t.Fatalf("results capacity = %d, want at least 8", cap(ctx.Results))
	}
}

func TestDeferredBodyEnsureOnce(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("hello-body"))
	ctx, err := NewRequestContextDeferredBody(req, "site-a", nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.DecodedBody != nil || ctx.bodyLoaded {
		t.Fatal("deferred constructor must not read body")
	}
	if err := ctx.EnsureBody(); err != nil {
		t.Fatal(err)
	}
	if got := string(ctx.DecodedBody); got != "hello-body" {
		t.Fatalf("decoded = %q", got)
	}
	// Idempotent
	if err := ctx.EnsureBody(); err != nil {
		t.Fatal(err)
	}
	if got := string(ctx.DecodedBody); got != "hello-body" {
		t.Fatalf("second ensure decoded = %q", got)
	}
	replayed, err := io.ReadAll(req.Body)
	if err != nil || string(replayed) != "hello-body" {
		t.Fatalf("replayed = %q err=%v", replayed, err)
	}
}

func TestClientIPIgnoresForwardedHeadersByDefault(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")
	req.Header.Set("X-Real-IP", "203.0.113.11")
	req.Header.Set("X-Forwarded-For", "203.0.113.12")

	if got := ClientIP(req); got != "198.51.100.20" {
		t.Fatalf("expected default client IP to use socket peer only, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesRequiresTrustedRemote(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("X-Real-IP", "203.0.113.10")

	if got := ClientIPWithTrustedProxies(req, []string{"10.0.0.0/8"}); got != "198.51.100.20" {
		t.Fatalf("expected remote address when proxy is untrusted, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesIgnoresCDNHeadersWithoutProviderBinding(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24"}); got != "198.51.100.20" {
		t.Fatalf("generic trusted CIDRs must not enable Cloudflare headers, got %q", got)
	}
}

func TestClientIPWithTrustedProxyProvidersUsesOnlyBoundProviderHeaders(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		header   string
		value    string
		want     string
	}{
		{name: "cloudflare", provider: "cloudflare", header: "CF-Connecting-IP", value: "203.0.113.20", want: "203.0.113.20"},
		{name: "aliyun", provider: "aliyun", header: "Ali-CDN-Real-IP", value: "203.0.113.21", want: "203.0.113.21"},
		{name: "vercel list", provider: "vercel", header: "X-Vercel-Forwarded-For", value: "203.0.113.22, 198.51.100.20", want: "203.0.113.22"},
		{name: "digitalocean", provider: "digitalocean", header: "DO-Connecting-IP", value: "203.0.113.23", want: "203.0.113.23"},
		{name: "azure", provider: "azure", header: "X-Azure-ClientIP", value: "203.0.113.24", want: "203.0.113.24"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
			req.RemoteAddr = "198.51.100.20:1234"
			req.Header.Set(tc.header, tc.value)

			providers := map[string][]string{tc.provider: {"198.51.100.0/24"}}
			if got := ClientIPWithTrustedProxyProviders(req, nil, providers); got != tc.want {
				t.Fatalf("expected %s, got %q", tc.want, got)
			}
		})
	}
}

func TestClientIPWithTrustedProxyProvidersRequiresProviderCIDRMatch(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "203.0.113.10")

	got := ClientIPWithTrustedProxyProviders(
		req,
		[]string{"198.51.100.0/24"},
		map[string][]string{"cloudflare": {"192.0.2.0/24"}},
	)
	if got != "198.51.100.20" {
		t.Fatalf("generic proxy must not supply a provider-bound header, got %q", got)
	}
}

func TestClientIPWithTrustedProxyProvidersDoesNotCrossProviderBindings(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("Fastly-Client-IP", "203.0.113.10")

	got := ClientIPWithTrustedProxyProviders(
		req,
		nil,
		map[string][]string{"cloudflare": {"198.51.100.0/24"}},
	)
	if got != "198.51.100.20" {
		t.Fatalf("Cloudflare binding must not enable Fastly headers, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesUsesForwardedForChain(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.5, 198.51.100.20")

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24", "10.0.0.0/8"}); got != "203.0.113.10" {
		t.Fatalf("expected first untrusted forwarded IP, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesPrefersValidatedChainOverSpoofableVendorHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("CF-Connecting-IP", "192.0.2.99")
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 198.51.100.20")

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.0/24"}); got != "203.0.113.10" {
		t.Fatalf("expected validated forwarding chain, got %q", got)
	}
}

func TestClientIPWithTrustedProxiesParsesForwardedHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("Forwarded", `for="[2001:db8::10]:443";proto=https`)

	if got := ClientIPWithTrustedProxies(req, []string{"198.51.100.20"}); got != "2001:db8::10" {
		t.Fatalf("expected forwarded IPv6 address, got %q", got)
	}
}

func TestProviderCIDRsParticipateInValidatedForwardedChain(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Add("X-Forwarded-For", "203.0.113.10")
	req.Header.Add("X-Forwarded-For", "198.51.100.20")

	got := ClientIPWithTrustedProxyProviders(
		req,
		nil,
		map[string][]string{"cloudflare": {"198.51.100.0/24"}},
	)
	if got != "203.0.113.10" {
		t.Fatalf("expected provider CIDR to validate the forwarding chain, got %q", got)
	}
}

// compressedRequestBody builds a request whose body is encoded with the named
// Content-Encoding and reads it through the public request-context path, which
// is what the proxy maps to an HTTP status.
func compressedRequestBody(t *testing.T, siteID, encoding string, body []byte) (string, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.test/submit", bytes.NewReader(body))
	req.Header.Set("Content-Encoding", encoding)
	reqCtx, err := NewRequestContextDeferredBody(req, siteID, nil, 1<<20)
	if err != nil {
		t.Fatalf("request context: %v", err)
	}
	readErr := reqCtx.EnsureBodyContext(req.Context())
	if readErr != nil {
		return "", readErr
	}
	return string(reqCtx.DecodedBody), nil
}

func brotliBody(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestDecodedBodySupportsBrotli pins the client-compat fix: a legal br body used
// to fail inspection with a generic error, which the proxy reported as 400.
// Brotli is a supported browser encoding, so the body must be inspected instead.
func TestDecodedBodySupportsBrotli(t *testing.T) {
	plain := `{"q":"hello union select 1"}`
	got, err := compressedRequestBody(t, "site-br", "br", brotliBody(t, []byte(plain)))
	if err != nil {
		t.Fatalf("legal br body rejected: %v", err)
	}
	if got != plain {
		t.Fatalf("decoded body=%q, want %q", got, plain)
	}
}

// TestDecodedBodySupportsZlibAndRawDeflate covers both deflate dialects: RFC
// 1950 says zlib, but many clients send raw DEFLATE. Both must be inspected.
func TestDecodedBodySupportsZlibAndRawDeflate(t *testing.T) {
	plain := []byte(`{"q":"hello union select 1"}`)

	var zlibWrapped bytes.Buffer
	zw := zlib.NewWriter(&zlibWrapped)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var raw bytes.Buffer
	fw, err := flate.NewWriter(&raw, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}

	for name, body := range map[string][]byte{"zlib-wrapped": zlibWrapped.Bytes(), "raw": raw.Bytes()} {
		got, err := compressedRequestBody(t, "site-deflate-"+name, "deflate", body)
		if err != nil {
			t.Fatalf("%s deflate body rejected: %v", name, err)
		}
		if got != string(plain) {
			t.Fatalf("%s deflate decoded body=%q, want %q", name, got, plain)
		}
	}
}

// zstdFrame is a zstd-compressed `{"q":"hello world"}` produced by zstd 1.5.7.
// The engine has no zstd decoder (adding one would need a new dependency), so the
// contract is a typed error the proxy can map to 415 instead of a generic 400.
var zstdFrame = []byte{
	0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x13, 0x99, 0x00, 0x00, 0x7b, 0x22, 0x71,
	0x22, 0x3a, 0x22, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72,
	0x6c, 0x64, 0x22, 0x7d, 0x4f, 0x64, 0xc0, 0x92,
}

func TestDecodedBodyReportsUnsupportedEncodingAsTypedError(t *testing.T) {
	for name, tc := range map[string][]byte{
		"zstd":             zstdFrame,
		"compress":         []byte("not really compressed"),
		"application/x-br": []byte("unknown alias"),
	} {
		_, err := compressedRequestBody(t, "site-unsupported-"+strings.ReplaceAll(name, "/", "-"), name, tc)
		if !errors.Is(err, ErrUnsupportedContentEncoding) {
			t.Fatalf("%s: error=%v, want ErrUnsupportedContentEncoding (proxy maps it to 415)", name, err)
		}
		if errors.Is(err, ErrRequestBodyTooLarge) {
			t.Fatalf("%s: unsupported encoding must not be reported as a size violation", name)
		}
	}
}
