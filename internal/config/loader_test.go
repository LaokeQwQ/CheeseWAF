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

func TestValidateHTTP3RequiresCertificate(t *testing.T) {
	cfg := Default()
	cfg.Server.HTTP3.Enabled = true
	cfg.TLS.CertFile = ""
	cfg.TLS.KeyFile = ""

	if err := Validate(&cfg); err == nil {
		t.Fatal("expected HTTP/3 certificate validation error")
	}
}

func TestValidatePostgreSQLTableIdentifier(t *testing.T) {
	cfg := Default()
	cfg.Storage.PostgreSQL.Enabled = true
	cfg.Storage.PostgreSQL.DSN = "postgres://example"
	cfg.Storage.PostgreSQL.Table = "public.logs;drop"

	if err := Validate(&cfg); err == nil {
		t.Fatal("expected unsafe PostgreSQL table validation error")
	}
}
