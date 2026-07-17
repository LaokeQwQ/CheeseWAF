package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validS3CAPTCHAConfig(t *testing.T) Config {
	t.Helper()
	cfg := Default()
	cfg.CAPTCHAAssets.Backend = "s3"
	cfg.CAPTCHAAssets.S3.Endpoint = "https://s3.example.com"
	cfg.CAPTCHAAssets.S3.Bucket = "captcha"
	cfg.CAPTCHAAssets.S3.Region = "us-east-1"
	cfg.CAPTCHAAssets.S3.CredentialFile = filepath.Join(t.TempDir(), "credential.json")
	cfg.CAPTCHAAssets.S3.MetadataKeyFile = filepath.Join(t.TempDir(), "metadata.key")
	return cfg
}

func TestCAPTCHAAssetsLoadDefaultsZeroRequestTimeoutAndPrivateOptInOff(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("captcha_assets:\n  backend: local\n  local:\n    path: ./captcha\n")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAPTCHAAssets.S3.RequestTimeout != Default().CAPTCHAAssets.S3.RequestTimeout {
		t.Fatalf("timeout was not defaulted: %s", cfg.CAPTCHAAssets.S3.RequestTimeout)
	}
	if cfg.CAPTCHAAssets.S3.AllowPrivateEndpoint {
		t.Fatal("private S3 endpoints must default off")
	}
}

func TestCAPTCHAAssetsS3EndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"http://127.0.0.1:9000", "http://169.254.169.254", "http://10.0.0.1", "http://0.0.0.0", "http://224.0.0.1"} {
		t.Run(endpoint, func(t *testing.T) {
			cfg := validS3CAPTCHAConfig(t)
			cfg.CAPTCHAAssets.S3.Endpoint = endpoint
			cfg.CAPTCHAAssets.S3.UseTLS = false
			if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "must be public") {
				t.Fatalf("expected public endpoint rejection, got %v", err)
			}
			cfg.CAPTCHAAssets.S3.AllowPrivateEndpoint = true
			if err := Validate(&cfg); err != nil {
				t.Fatalf("explicit private endpoint opt-in failed: %v", err)
			}
		})
	}
}

func TestCAPTCHAAssetsS3TimeoutAndTLSValidation(t *testing.T) {
	cfg := validS3CAPTCHAConfig(t)
	cfg.CAPTCHAAssets.S3.RequestTimeout = 0
	if err := Validate(&cfg); err == nil {
		t.Fatal("raw zero timeout must fail validation before defaulting")
	}
	cfg.CAPTCHAAssets.S3.RequestTimeout = time.Second
	cfg.CAPTCHAAssets.S3.Endpoint = "http://s3.example.com"
	cfg.CAPTCHAAssets.S3.UseTLS = true
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("expected TLS validation error, got %v", err)
	}
}
