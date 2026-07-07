package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestClusterStatusStandalone(t *testing.T) {
	h := New(Options{Config: ptrClusterConfig(config.Default())})
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	rec := httptest.NewRecorder()
	h.ClusterStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope dto.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data, ok := envelope.Data.(map[string]any)
	if !ok {
		t.Fatalf("unexpected data: %#v", envelope.Data)
	}
	if data["mode"] != "standalone" || data["product_mode_label"] != "单机模式" {
		t.Fatalf("unexpected cluster status: %#v", data)
	}
}

func ptrClusterConfig(cfg config.Config) *config.Config {
	return &cfg
}
