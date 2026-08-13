package config

import (
	"strings"
	"testing"
)

func TestParseFileLogSize(t *testing.T) {
	tests := []struct {
		raw  string
		want int64
	}{
		{raw: "1KB", want: 1 << 10},
		{raw: "2 MiB", want: 2 << 20},
		{raw: "3GB", want: 3 << 30},
		{raw: "4096", want: 4096},
	}
	for _, test := range tests {
		got, err := ParseFileLogSize(test.raw)
		if err != nil || got != test.want {
			t.Errorf("ParseFileLogSize(%q) = %d, %v; want %d", test.raw, got, err, test.want)
		}
	}
	for _, raw := range []string{"", "0B", "1.5MB", "-1MB", "1XB"} {
		if _, err := ParseFileLogSize(raw); err == nil {
			t.Errorf("ParseFileLogSize(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestValidatorFileLogRotationBounds(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "valid rotation settings",
			mutate: func(cfg *Config) {
				cfg.Logging.Output.File.MaxSize = "1MiB"
				cfg.Logging.Output.File.MaxBackups = 2
			},
		},
		{
			name: "size too small",
			mutate: func(cfg *Config) {
				cfg.Logging.Output.File.MaxSize = "512B"
			},
			wantErr: "max_size must be between",
		},
		{
			name: "backup count too large",
			mutate: func(cfg *Config) {
				cfg.Logging.Output.File.MaxBackups = maxFileLogBackupCount + 1
			},
			wantErr: "max_backups must be between",
		},
		{
			name: "invalid size syntax",
			mutate: func(cfg *Config) {
				cfg.Logging.Output.File.MaxSize = "not-a-size"
			},
			wantErr: "max_size is invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.mutate(&cfg)
			err := Validate(&cfg)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected error containing %q, got %v", test.wantErr, err)
			}
		})
	}
}
