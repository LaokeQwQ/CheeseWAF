package response

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/tamper"
)

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error { r.closed = true; return nil }

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingReadCloser) Close() error             { return nil }

// Sensitive patterns come from config and are compiled once at construction.
// Config validation (validateResponseInspection) only checks that they compile,
// so CompileSafe is the only complexity bound on them.
func TestNewRejectsSensitivePatternOverComplexityBudget(t *testing.T) {
	if _, err := New(config.ResponseInspectionConfig{
		Enabled:           true,
		SensitivePatterns: []string{strings.Repeat(`[\s\S]*`, 11)},
	}); err == nil {
		t.Fatal("New accepted a sensitive pattern over the complexity budget")
	}
}

// The gate must not reject the shipped defaults or a realistic alternation-heavy
// pattern, otherwise installing it would wedge response inspection at startup.
func TestNewAcceptsDefaultAndRealisticSensitivePatterns(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true, SensitivePatterns: []string{
		`AKIA[0-9A-Z]{16}`,
		`(?i)password\s*[=:]\s*['"]?[^'"\s]+`,
		`(?i)BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`aws_key = AKIAIOSFODNN7EXAMPLE`)
	finding := inspector.Inspect(body)
	if finding == nil || finding.DetectorID != "response.inspector" {
		t.Fatalf("expected finding, got %+v", finding)
	}
}

func TestDefaultSensitivePatternsPassComplexityGate(t *testing.T) {
	if _, err := New(config.ResponseInspectionConfig{Enabled: true}); err != nil {
		t.Fatalf("default sensitive patterns must pass the gate: %v", err)
	}
}

func TestInspectHTTPChecksCapturedPrefixWhenResponseExceedsLimit(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 32, SensitivePatterns: []string{`SECRET-PREFIX`}})
	if err != nil {
		t.Fatal(err)
	}
	body := "SECRET-PREFIX" + strings.Repeat("x", 64)
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	finding, err := inspector.InspectHTTP(resp)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil {
		t.Fatal("expected finding")
	}
	replayed, err := io.ReadAll(resp.Body)
	if err != nil || string(replayed) != body {
		t.Fatalf("replay len=%d err=%v", len(replayed), err)
	}
}

func TestNewRejectsInvalidPattern(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true, SensitivePatterns: []string{"["}})
	if err == nil || inspector != nil {
		t.Fatalf("got %#v, %v", inspector, err)
	}
}

func TestNewRejectsDisabledTamperConfiguration(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{
		TamperKey:       "01234567890123456789012345678901",
		TamperSnapshots: []config.TamperSnapshotConfig{{URL: "/", MAC: strings.Repeat("0", 64)}},
	})
	if err == nil || inspector != nil {
		t.Fatalf("disabled tamper config got %#v, %v", inspector, err)
	}
}

func TestDefaultPatternsDetectPassword(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if finding := inspector.Inspect([]byte(`password=hunter2`)); finding == nil {
		t.Fatal("finding = nil")
	}
}

func TestDisabledAndNilInspectorDoNotInspect(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if inspector.Enabled() || inspector.Inspect([]byte("password=secret")) != nil {
		t.Fatal("disabled inspector inspected")
	}
	var nilInspector *Inspector
	if nilInspector.Enabled() || nilInspector.Inspect(nil) != nil {
		t.Fatal("nil inspector inspected")
	}
	if finding, err := nilInspector.InspectHTTP(nil); finding != nil || err != nil {
		t.Fatalf("got %#v, %v", finding, err)
	}
}

func TestInspectHTTPReplaysCompleteBodyAndUpdatesLength(t *testing.T) {
	inspector, _ := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 128, SensitivePatterns: []string{"token"}})
	original := &trackingReadCloser{Reader: strings.NewReader("token=value")}
	resp := &http.Response{Header: make(http.Header), Body: original, ContentLength: -1}
	finding, err := inspector.InspectHTTP(resp)
	if err != nil || finding == nil {
		t.Fatalf("got %#v, %v", finding, err)
	}
	if !original.closed {
		t.Fatal("original body not closed")
	}
	replayed, err := io.ReadAll(resp.Body)
	if err != nil || string(replayed) != "token=value" {
		t.Fatalf("replayed=%q err=%v", replayed, err)
	}
	if resp.ContentLength != 11 || resp.Header.Get("Content-Length") != "11" {
		t.Fatalf("length=%d header=%q", resp.ContentLength, resp.Header.Get("Content-Length"))
	}
}

func TestInspectHTTPReturnsReadErrorWithoutReplacingBody(t *testing.T) {
	inspector, _ := New(config.ResponseInspectionConfig{Enabled: true, SensitivePatterns: []string{"secret"}})
	original := failingReadCloser{}
	resp := &http.Response{Header: make(http.Header), Body: original}
	finding, err := inspector.InspectHTTP(resp)
	if finding != nil || err == nil || resp.Body != original {
		t.Fatalf("got %#v, %v", finding, err)
	}
}

func TestOversizedReplayClosesOriginalBody(t *testing.T) {
	inspector, _ := New(config.ResponseInspectionConfig{Enabled: true, MaxBodyBytes: 4, SensitivePatterns: []string{"none"}})
	original := &trackingReadCloser{Reader: strings.NewReader("abcdefgh")}
	resp := &http.Response{Header: make(http.Header), Body: original}
	if _, err := inspector.InspectHTTP(resp); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !original.closed {
		t.Fatal("original body not closed")
	}
}

func TestInspectHTTPForRequestVerifiesURLBoundTamperSnapshot(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	snapshot, err := tamper.Capture(key, "/assets/app.js?v=1", []byte("clean"), time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled: true, MaxBodyBytes: 64, TamperKey: string(key),
		TamperSnapshots: []config.TamperSnapshotConfig{{
			URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size, CapturedAt: snapshot.CapturedAt,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		url        string
		body       string
		wantTamper bool
	}{
		{name: "matching body", url: "https://example.test/assets/app.js?v=1", body: "clean"},
		{name: "changed body", url: "https://example.test/assets/app.js?v=1", body: "evil!", wantTamper: true},
		{name: "different query has no baseline", url: "https://example.test/assets/app.js?v=2", body: "evil!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, requestErr := http.NewRequest(http.MethodGet, tc.url, nil)
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}
			finding, inspectErr := inspector.InspectHTTPForRequest(resp, req)
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if got := finding != nil && finding.DetectorID == "protection.tamper"; got != tc.wantTamper {
				t.Fatalf("finding=%+v wantTamper=%v", finding, tc.wantTamper)
			}
			replayed, readErr := io.ReadAll(resp.Body)
			if readErr != nil || string(replayed) != tc.body {
				t.Fatalf("replayed=%q err=%v", replayed, readErr)
			}
		})
	}
}

func TestTamperSnapshotReportsUnverifiableTargetWithoutTruncationPass(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	snapshot, err := tamper.Capture(key, "/index.html", []byte("good"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled: true, MaxBodyBytes: 4, TamperKey: string(key),
		TamperSnapshots: []config.TamperSnapshotConfig{{URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := mustResponseRequest(t, http.MethodGet, "https://example.test/index.html")
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader("good-extra"))}
	finding, err := inspector.InspectHTTPForRequest(resp, req)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.DetectorID != "protection.tamper" || finding.Reason != "size_limit" {
		t.Fatalf("oversized target finding = %+v", finding)
	}
}

func TestTamperSnapshotSkipsHEADAndFlagsStreamingGET(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	snapshot, err := tamper.Capture(key, "/events", []byte("clean"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled: true, MaxBodyBytes: 64, TamperKey: string(key),
		TamperSnapshots: []config.TamperSnapshotConfig{{URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method     string
		wantReason string
	}{
		{method: http.MethodHead},
		{method: http.MethodGet, wantReason: "streaming_response"},
	} {
		resp := &http.Response{
			Header: http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:   io.NopCloser(strings.NewReader("changed")),
		}
		finding, inspectErr := inspector.InspectHTTPForRequest(resp, mustResponseRequest(t, tc.method, "https://example.test/events"))
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		if tc.wantReason == "" && finding != nil {
			t.Fatalf("HEAD response produced finding: %+v", finding)
		}
		if tc.wantReason != "" && (finding == nil || finding.Reason != tc.wantReason) {
			t.Fatalf("streaming finding = %+v", finding)
		}
	}
}

// A coverage gap (size limit, streaming media, unsupported encoding) is not
// evidence of sensitive data, but it is also not proof of absence. The fail
// mode decides which of those two facts wins. `closed` is the default: an
// uninspectable body must not reach the client.
func TestInspectionIncompleteSizeLimitFailModes(t *testing.T) {
	body := "SECRET-" + strings.Repeat("x", 64)
	for _, tc := range []struct {
		mode       string
		wantAction string
	}{
		{mode: config.ResponseFailModeOpen, wantAction: ""},
		{mode: config.ResponseFailModeObserve, wantAction: engine.ActionLog.String()},
		{mode: config.ResponseFailModeClosed, wantAction: engine.ActionBlock.String()},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			inspector := newFailModeInspector(t, tc.mode)
			resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
			finding, err := inspector.InspectHTTP(resp)
			if err != nil {
				t.Fatal(err)
			}
			assertIncompleteFinding(t, finding, tc.mode, tc.wantAction, "size_limit")
			replayed, err := io.ReadAll(resp.Body)
			if err != nil || string(replayed) != body {
				t.Fatalf("body must stay replayable for the proxy: len=%d err=%v", len(replayed), err)
			}
		})
	}
}

func TestInspectionIncompleteStreamingFailModes(t *testing.T) {
	const body = "event: ping\n\n"
	for _, tc := range []struct {
		mode       string
		wantNil    bool
		wantAction string
	}{
		{mode: config.ResponseFailModeOpen, wantNil: true},
		{mode: config.ResponseFailModeObserve, wantAction: engine.ActionLog.String()},
		{mode: config.ResponseFailModeClosed, wantAction: engine.ActionBlock.String()},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			inspector := newFailModeInspector(t, tc.mode)
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:   io.NopCloser(strings.NewReader(body)),
			}
			finding, err := inspector.InspectHTTP(resp)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNil {
				if finding != nil {
					t.Fatalf("open mode must keep the pre-policy streaming behaviour, got %+v", finding)
				}
				return
			}
			assertIncompleteFinding(t, finding, tc.mode, tc.wantAction, "streaming_response")
		})
	}
}

func TestInspectionIncompleteUnsupportedEncodingFailModes(t *testing.T) {
	for _, tc := range []struct {
		mode       string
		wantAction string
	}{
		{mode: config.ResponseFailModeOpen, wantAction: ""},
		{mode: config.ResponseFailModeObserve, wantAction: engine.ActionLog.String()},
		{mode: config.ResponseFailModeClosed, wantAction: engine.ActionBlock.String()},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			inspector := newFailModeInspector(t, tc.mode)
			resp := &http.Response{
				Header: http.Header{"Content-Encoding": []string{"zstd"}},
				Body:   io.NopCloser(strings.NewReader("SECRET-x")),
			}
			finding, err := inspector.InspectHTTP(resp)
			if err != nil {
				t.Fatal(err)
			}
			assertIncompleteFinding(t, finding, tc.mode, tc.wantAction, "unsupported_or_invalid_encoding")
		})
	}
}

func TestNewDefaultsFailModeToObserve(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := inspector.FailMode(); got != config.ResponseFailModeObserve {
		t.Fatalf("default fail mode = %q, want %q", got, config.ResponseFailModeObserve)
	}
}

// A typo must not silently select a different exposure policy.
func TestNewRejectsUnknownFailMode(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled:    true,
		Inspection: config.ResponseInspectionPolicy{FailMode: "clossed"},
	})
	if err == nil || inspector != nil {
		t.Fatalf("got %#v, %v", inspector, err)
	}
}

func newFailModeInspector(t *testing.T, mode string) *Inspector {
	t.Helper()
	inspector, err := New(config.ResponseInspectionConfig{
		Enabled:           true,
		MaxBodyBytes:      8,
		SensitivePatterns: []string{`SECRET-`},
		Inspection:        config.ResponseInspectionPolicy{FailMode: mode},
	})
	if err != nil {
		t.Fatalf("New(fail_mode=%q): %v", mode, err)
	}
	return inspector
}

func assertIncompleteFinding(t *testing.T, finding *Finding, mode, wantAction, wantReason string) {
	t.Helper()
	if finding == nil {
		t.Fatalf("fail_mode=%s reported no coverage gap", mode)
	}
	if !finding.Incomplete {
		t.Fatalf("fail_mode=%s finding is not marked incomplete: %+v", mode, finding)
	}
	if finding.Reason != wantReason {
		t.Fatalf("fail_mode=%s reason = %q, want %q", mode, finding.Reason, wantReason)
	}
	if finding.FailMode != mode {
		t.Fatalf("fail_mode=%s recorded as %q", mode, finding.FailMode)
	}
	if finding.Action != wantAction {
		t.Fatalf("fail_mode=%s action = %q, want %q", mode, finding.Action, wantAction)
	}
	if mode == config.ResponseFailModeClosed && finding.Severity != "high" {
		t.Fatalf("closed finding severity = %q, want high", finding.Severity)
	}
}

func mustResponseRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
