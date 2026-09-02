package webshell

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestDetectorBlocksEncodedUploadThroughPipeline(t *testing.T) {
	detector := NewDetector(DetectorConfig{Mode: "block"})
	pipeline := engine.NewPipeline(detector)
	body := `code=%253C%253Fphp%2520system%2528%2524_GET%255B%2522cmd%2522%255D%2529%253B%2520%253F%253E`
	req, err := http.NewRequest(http.MethodPost, "https://example.test/upload", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqCtx, err := engine.NewRequestContext(req, "site-a")
	if err != nil {
		t.Fatal(err)
	}
	result, err := pipeline.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.DetectorID != "protection.webshell" || result.Action != engine.ActionBlock {
		t.Fatalf("encoded upload did not block through pipeline: %+v", result)
	}
}

func TestDetectorBlocksDeferredBodyUploadThroughPipeline(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://example.test/upload.php", strings.NewReader(`<?php system($_GET["cmd"]); ?>`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	reqCtx, err := engine.NewRequestContextDeferredBody(req, "site-a", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.NewPipeline(NewDetector(DetectorConfig{Mode: "block"})).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.DetectorID != "protection.webshell" || result.Action != engine.ActionBlock {
		t.Fatalf("deferred upload did not block through pipeline: %+v", result)
	}
}

func TestDetectorRunsBeforeConcurrentSemanticDetection(t *testing.T) {
	if priority := NewDetector(DetectorConfig{}).Priority(); priority >= 290 {
		t.Fatalf("webshell detector priority = %d, want sequential pre-filter priority", priority)
	}
}

func TestDetectorFailsClosedForOversizedExecutableCandidate(t *testing.T) {
	detector := NewDetector(DetectorConfig{Mode: "block", MaxCandidateBytes: 64})
	body := strings.Repeat("A", 80) + `<?php system($_GET["cmd"]); ?>`
	req, err := http.NewRequest(http.MethodPost, "https://example.test/upload.php", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "site-a")
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != engine.ActionBlock || !strings.Contains(result.Message, "scan limit") {
		t.Fatalf("oversized executable candidate silently passed: %+v", result)
	}
}

func TestDetectorFailsClosedWhenItsScanDeadlineExpires(t *testing.T) {
	detector := NewDetector(DetectorConfig{Mode: "block", Timeout: time.Nanosecond})
	body := strings.Repeat("<?php $value = 'safe'; ?>", 4096)
	req, err := http.NewRequest(http.MethodPost, "https://example.test/upload.php", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	reqCtx, err := engine.NewRequestContext(req, "site-a")
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Action != engine.ActionBlock || !strings.Contains(result.Message, "deadline") {
		t.Fatalf("scan timeout silently passed: %+v", result)
	}
}

func TestDetectorEnforcesConcurrencyLimit(t *testing.T) {
	detector := NewDetector(DetectorConfig{Mode: "block", MaxConcurrent: 1})
	detector.slots <- struct{}{}
	defer func() { <-detector.slots }()
	req := mustDetectorRequest(t, http.MethodGet, "https://example.test/")
	reqCtx, err := engine.NewRequestContext(req, "site-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Detect(context.Background(), reqCtx); !errors.Is(err, engine.ErrDetectionOverload) {
		t.Fatalf("concurrency limit error = %v", err)
	}
}

func mustDetectorRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
