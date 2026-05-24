package config

import "testing"

func TestLoadSampleConfig(t *testing.T) {
	cfg, err := Load("../../configs/cheesewaf.yaml")
	if err != nil {
		t.Fatalf("Load sample config: %v", err)
	}
	if cfg.Server.Listen == "" || cfg.Server.AdminListen == "" {
		t.Fatalf("server listeners should be populated: %+v", cfg.Server)
	}
	if len(cfg.Sites) != 1 {
		t.Fatalf("expected one sample site, got %d", len(cfg.Sites))
	}
}
