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
