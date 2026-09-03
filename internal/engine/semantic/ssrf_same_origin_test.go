package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestSSRFRequestSchemeHonorsTrustedForwardedProto(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?url=https://192.168.171.131/admin", nil)
	req.Host = "192.168.171.131"
	req.RemoteAddr = "10.0.0.2:443"
	req.Header.Set("X-Forwarded-Proto", "https, http")
	if got := ssrfRequestScheme(req, []string{"10.0.0.0/8"}); got != "https" {
		t.Fatalf("trusted forwarded proto scheme = %q, want https", got)
	}
	req.RemoteAddr = "198.51.100.2:443"
	if got := ssrfRequestScheme(req, []string{"10.0.0.0/8"}); got != "http" {
		t.Fatalf("untrusted forwarded proto scheme = %q, want http", got)
	}
}

func sameOriginTelemetryRequest(t *testing.T, path string) *engine.RequestContext {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://192.168.171.131"+path, nil)
	req.Host = "192.168.171.131"
	return &engine.RequestContext{Request: req, HostValidated: true, Metadata: map[string]any{}}
}

func TestSSRFDetectorSuppressesSameOriginTelemetryReference(t *testing.T) {
	self := url.QueryEscape("http://192.168.171.131/dashboard/")
	reqCtx := sameOriginTelemetryRequest(t, "/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+self)
	got, err := NewSSRFDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("same-origin telemetry URL was treated as SSRF: %+v", got)
	}

	got, err = NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("analyzer treated same-origin telemetry URL as SSRF: %+v", got)
	}
}

func TestSSRFTelemetryGateRequiresValidatedHost(t *testing.T) {
	self := url.QueryEscape("http://192.168.171.131/dashboard/")
	reqCtx := sameOriginTelemetryRequest(t, "/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+self)
	reqCtx.HostValidated = false
	got, err := NewSSRFDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Category != "ssrf" {
		t.Fatalf("unvalidated Host must not enable telemetry suppression: %+v", got)
	}
}

func TestSSRFDetectorKeepsExplicitFetchAndCrossOriginTargetsBlockable(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{
			name: "explicit fetch route",
			path: "/fetch?wmcAction=wmcTrack&siteId=1&visitorId=v1&url=" + url.QueryEscape("http://192.168.171.131/admin"),
		},
		{
			name: "different private target",
			path: "/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url=" + url.QueryEscape("http://169.254.169.254/latest/meta-data"),
		},
		{
			name: "single url field",
			path: "/?url=" + url.QueryEscape("http://192.168.171.131/admin"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewSSRFDetector("block").Detect(context.Background(), sameOriginTelemetryRequest(t, tc.path))
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected || got.Category != "ssrf" {
				t.Fatalf("expected SSRF detection, got %+v", got)
			}
		})
	}
}

func TestSSRFDetectorSuppressesValidatedSameOriginLoginRedirect(t *testing.T) {
	self := url.QueryEscape("http://192.168.171.131/wp-admin/")
	queryCtx := sameOriginTelemetryRequest(t, "/wp-login.php?redirect_to="+self+"&reauth=1")
	if got, err := NewSSRFDetector("block").Detect(context.Background(), queryCtx); err != nil || got != nil {
		t.Fatalf("same-origin login redirect was treated as SSRF: %+v err=%v", got, err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://192.168.171.131/wp-login.php", strings.NewReader("redirect_to="+self+"&log=subscriber"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "192.168.171.131"
	formCtx := &engine.RequestContext{Request: req, HostValidated: true, Metadata: map[string]any{}}
	if got, err := NewSSRFDetector("block").Detect(context.Background(), formCtx); err != nil || got != nil {
		t.Fatalf("same-origin form redirect was treated as SSRF: %+v err=%v", got, err)
	}

	rawReq := httptest.NewRequest(http.MethodPost, "http://192.168.171.131/wp-login.php", strings.NewReader("log=subscriber&redirect_to="+self+"&testcookie=1"))
	rawReq.Host = "192.168.171.131"
	rawCtx := &engine.RequestContext{Request: rawReq, HostValidated: true, Metadata: map[string]any{}}
	if got, err := NewSSRFDetector("block").Detect(context.Background(), rawCtx); err != nil || got != nil {
		t.Fatalf("same-origin raw-form redirect was treated as SSRF: %+v err=%v", got, err)
	}
}

func TestSSRFDetectorKeepsCrossOriginRedirectAndFetchRouteBlockable(t *testing.T) {
	private := url.QueryEscape("http://169.254.169.254/latest/meta-data")
	for _, path := range []string{
		"/wp-login.php?redirect_to=" + private,
		"/fetch?redirect_to=" + private,
	} {
		t.Run(path, func(t *testing.T) {
			got, err := NewSSRFDetector("block").Detect(context.Background(), sameOriginTelemetryRequest(t, path))
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected || got.Category != "ssrf" {
				t.Fatalf("cross-origin/explicit fetch redirect was not detected: %+v", got)
			}
		})
	}
}

func TestSSRFSameOriginRequiresMatchingPortAndScheme(t *testing.T) {
	selfPort := url.QueryEscape("http://192.168.171.131:8080/admin")
	request := httptest.NewRequest(http.MethodGet, "http://192.168.171.131:8080/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+selfPort, nil)
	request.Host = "192.168.171.131:8080"
	ctx := &engine.RequestContext{Request: request, HostValidated: true, Metadata: map[string]any{}}
	if got, err := NewSSRFDetector("block").Detect(context.Background(), ctx); err != nil || got != nil {
		t.Fatalf("same host and port should be suppressed: %+v err=%v", got, err)
	}

	otherPort := url.QueryEscape("http://192.168.171.131:9000/admin")
	request = httptest.NewRequest(http.MethodGet, "http://192.168.171.131:8080/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+otherPort, nil)
	request.Host = "192.168.171.131:8080"
	ctx.Request = request
	got, err := NewSSRFDetector("block").Detect(context.Background(), ctx)
	if err != nil || got == nil || got.Category != "ssrf" {
		t.Fatalf("cross-port private target must remain blockable: %+v err=%v", got, err)
	}

	secure := url.QueryEscape("http://192.168.171.131/admin")
	request = httptest.NewRequest(http.MethodGet, "https://192.168.171.131/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+secure, nil)
	request.Host = "192.168.171.131"
	ctx.Request = request
	got, err = NewSSRFDetector("block").Detect(context.Background(), ctx)
	if err != nil || got == nil || got.Category != "ssrf" {
		t.Fatalf("cross-scheme private target must remain blockable: %+v err=%v", got, err)
	}
}

func TestSSRFRedirectRouteUsesPathTokens(t *testing.T) {
	self := url.QueryEscape("http://192.168.171.131/admin")
	request := httptest.NewRequest(http.MethodGet, "/author?redirect_to="+self, nil)
	request.Host = "192.168.171.131"
	ctx := &engine.RequestContext{Request: request, HostValidated: true, Metadata: map[string]any{}}
	got, err := NewSSRFDetector("block").Detect(context.Background(), ctx)
	if err != nil || got == nil || got.Category != "ssrf" {
		t.Fatalf("non-auth path must not enable redirect suppression: %+v err=%v", got, err)
	}
}

func TestPipelinePreservesHostValidationForSSRFGate(t *testing.T) {
	self := url.QueryEscape("http://192.168.171.131/admin")
	reqCtx := sameOriginTelemetryRequest(t, "/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+self)
	pipeline := engine.NewPipeline(NewAnalyzer("block", 2, "ssrf"))
	if got, err := pipeline.Detect(context.Background(), reqCtx); err != nil || (got != nil && got.Detected) {
		t.Fatalf("validated host provenance was lost in detector fork: %+v err=%v", got, err)
	}

	reqCtx = sameOriginTelemetryRequest(t, "/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+self)
	reqCtx.HostValidated = false
	got, err := pipeline.Detect(context.Background(), reqCtx)
	if err != nil || got == nil || got.Category != "ssrf" {
		t.Fatalf("unvalidated host must remain blockable through pipeline: %+v err=%v", got, err)
	}
}

func TestAnalyzerDoesNotReuseRequestScopedSSRFDecision(t *testing.T) {
	processCandidateCache.resetForTest()
	a := NewAnalyzer("block", 2, "ssrf")
	target := url.QueryEscape("http://192.168.171.131/admin")

	first := sameOriginTelemetryRequest(t, "/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+target)
	if got, err := a.Detect(context.Background(), first); err != nil || got != nil {
		t.Fatalf("same-origin telemetry should be suppressed, got=%+v err=%v", got, err)
	}

	crossOriginReq := httptest.NewRequest(http.MethodGet, "http://192.168.171.132/?wmcAction=wmcTrack&siteId=1&visitorId=v1&url="+target, nil)
	crossOriginReq.Host = "192.168.171.132"
	second := &engine.RequestContext{Request: crossOriginReq, HostValidated: true, Metadata: map[string]any{}}
	got, err := a.Detect(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Category != "ssrf" {
		t.Fatalf("cross-origin private target reused a suppressed cache result: %+v", got)
	}
}
