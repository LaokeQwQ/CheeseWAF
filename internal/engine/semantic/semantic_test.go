package semantic

import (
	"context"
	"net/http"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestSQLDetectorBlocksClassicPayload(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/items?id=1%27%20OR%20%271%27%3D%271", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewSQLDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Action != engine.ActionBlock {
		t.Fatalf("expected SQLi block, got %+v", result)
	}
}

func TestXSSDetectorBlocksScriptPayload(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewXSSDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Detected || result.Category != "xss" {
		t.Fatalf("expected XSS detection, got %+v", result)
	}
}

func TestPhase2SemanticDetectors(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		detector engine.Detector
		category string
	}{
		{name: "rce", target: "/run?cmd=1%3Bcat%20/etc/passwd", detector: NewRCEDetector("block"), category: "rce"},
		{name: "lfi", target: "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", detector: NewLFIDetector("block"), category: "lfi"},
		{name: "xxe", target: "/xml?body=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file%3A///etc/passwd%22%3E%5D%3E", detector: NewXXEDetector("block"), category: "xxe"},
		{name: "ssrf", target: "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data", detector: NewSSRFDetector("block"), category: "ssrf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, tc.target, nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := tc.detector.Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || !result.Detected || result.Category != tc.category {
				t.Fatalf("expected %s detection, got %+v", tc.category, result)
			}
		})
	}
}
