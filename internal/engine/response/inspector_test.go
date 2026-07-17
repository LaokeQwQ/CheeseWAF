package response

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error { r.closed = true; return nil }

type failingReadCloser struct{}

func (failingReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingReadCloser) Close() error             { return nil }

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
