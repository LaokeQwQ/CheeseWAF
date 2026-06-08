package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestImportThreatIntelNotifiesProtectionReload(t *testing.T) {
	cfg := config.Default()
	cfg.Protection.IP.Whitelist = nil
	cfg.Protection.IP.Blacklist = nil
	configPath := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(configPath, &cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	var reloaded config.ProtectionConfig
	handler := New(Options{
		Config:     &cfg,
		ConfigPath: configPath,
		OnProtectionChanged: func(next config.ProtectionConfig) error {
			reloaded = next
			return nil
		},
	})
	body := map[string]any{
		"format":   "csv",
		"source":   "feed-a",
		"contents": "ip,severity,action,confidence\n203.0.113.10,high,challenge,90\n",
	}
	raw, _ := json.Marshal(body)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/ip/threat-intel/import", bytes.NewReader(raw))
	handler.ImportThreatIntel(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected import ok, code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(reloaded.IP.ThreatIntel) != 1 {
		t.Fatalf("expected protection reload with imported intel, got %+v", reloaded.IP.ThreatIntel)
	}
	if reloaded.IP.ThreatIntel[0].Confidence != 0.9 || reloaded.IP.ThreatIntel[0].Action != "challenge" {
		t.Fatalf("unexpected imported intel: %+v", reloaded.IP.ThreatIntel[0])
	}
}
