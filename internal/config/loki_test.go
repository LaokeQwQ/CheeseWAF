package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateLokiStorageEndpointGuard(t *testing.T) {
	cfg := Default()
	cfg.Storage.Loki.Enabled = true
	cfg.Storage.Loki.Endpoint = "http://169.254.169.254/loki/api/v1/push"
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "storage.loki.endpoint") {
		t.Fatalf("expected unsafe loki endpoint rejected, got %v", err)
	}

	cfg = Default()
	cfg.Storage.Loki.Enabled = true
	cfg.Storage.Loki.Endpoint = "http://127.0.0.1:3100"
	cfg.Storage.Loki.AllowPrivateEndpoint = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected explicitly allowed private loki endpoint to validate: %v", err)
	}
}

func TestValidateLokiRequiresEndpointWhenEnabled(t *testing.T) {
	cfg := Default()
	cfg.Storage.Loki.Enabled = true
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "storage.loki.endpoint is required") {
		t.Fatalf("expected missing loki endpoint rejected, got %v", err)
	}
}

func TestValidateLokiRejectsInvalidLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
	}{
		{name: "dash in name", labels: map[string]string{"bad-label": "x"}},
		{name: "reserved prefix", labels: map[string]string{"__name__": "x"}},
		{name: "empty value", labels: map[string]string{"env": "  "}},
		{name: "leading digit", labels: map[string]string{"1env": "x"}},
		{name: "static site_id", labels: map[string]string{"site_id": "edge"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Storage.Loki.Enabled = true
			cfg.Storage.Loki.Endpoint = "http://127.0.0.1:3100"
			cfg.Storage.Loki.AllowPrivateEndpoint = true
			cfg.Storage.Loki.Labels = tc.labels
			if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "storage.loki.labels") {
				t.Fatalf("expected invalid loki labels rejected, got %v", err)
			}
		})
	}

	if err := ValidateLokiLabels(map[string]string{"job": "cheesewaf", "env_name": "prod-1"}); err != nil {
		t.Fatalf("expected valid labels accepted: %v", err)
	}
}

func TestApplyDefaultsFillsLokiDefaults(t *testing.T) {
	cfg := Default()
	cfg.Storage.Loki = LokiConfig{}
	applyDefaults(&cfg)
	if cfg.Storage.Loki.Timeout != 10*time.Second {
		t.Fatalf("expected default loki timeout 10s, got %s", cfg.Storage.Loki.Timeout)
	}
	if cfg.Storage.Loki.Labels == nil {
		t.Fatal("expected loki labels map to be initialized")
	}
}
