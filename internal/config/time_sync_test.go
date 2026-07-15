package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDefaultTimeSyncConfig(t *testing.T) {
	cfg := Default()
	got := cfg.TimeSync

	if !got.Enabled {
		t.Fatal("time synchronization should be enabled by default")
	}
	if got.SelectionInterval != 24*time.Hour {
		t.Fatalf("selection interval = %s, want 24h", got.SelectionInterval)
	}
	if got.SyncInterval != 30*time.Minute {
		t.Fatalf("sync interval = %s, want 30m", got.SyncInterval)
	}
	if got.Timeout != 2*time.Second {
		t.Fatalf("timeout = %s, want 2s", got.Timeout)
	}
	if got.SamplesPerSource != 3 {
		t.Fatalf("samples per source = %d, want 3", got.SamplesPerSource)
	}
	if got.MaxAcceptedOffset != 5*time.Minute {
		t.Fatalf("max accepted offset = %s, want 5m", got.MaxAcceptedOffset)
	}
	if got.MaxAcceptedOffset <= 0 || got.MaxRootDispersion <= 0 || got.ConsensusTolerance <= 0 {
		t.Fatalf("time acceptance defaults must be positive: %+v", got)
	}

	wantSources := []string{
		"time.cloudflare.com",
		"time.google.com",
		"time.aws.com",
		"time.apple.com",
		"ntp.aliyun.com",
		"time1.cloud.tencent.com",
		"ntp.ubuntu.com",
		"pool.ntp.org",
	}
	seen := make(map[string]struct{}, len(got.Sources))
	for _, source := range got.Sources {
		key := strings.ToLower(strings.TrimSuffix(source, "."))
		if _, exists := seen[key]; exists {
			t.Fatalf("default time source %q is duplicated", source)
		}
		seen[key] = struct{}{}
	}
	for _, source := range wantSources {
		if _, exists := seen[source]; !exists {
			t.Errorf("default time sources do not include %q", source)
		}
	}
	if _, exists := seen["time.tencent.com"]; exists {
		t.Error("deprecated Tencent time source should not be present")
	}

	got.Sources[0] = "mutated.example"
	if Default().TimeSync.Sources[0] == "mutated.example" {
		t.Fatal("Default must return an independent time source slice")
	}
}

func TestTimeSyncEnabledUsesYAMLFieldPresence(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "time sync section absent", raw: "deployment:\n  mode: standalone\n", want: true},
		{name: "enabled field absent", raw: "time_sync:\n  sync_interval: 1h\n", want: true},
		{name: "explicitly disabled", raw: "time_sync:\n  enabled: false\n", want: false},
		{name: "explicitly enabled", raw: "time_sync:\n  enabled: true\n", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.raw), &cfg); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if cfg.TimeSync.Enabled != tc.want {
				t.Fatalf("time_sync.enabled = %t, want %t", cfg.TimeSync.Enabled, tc.want)
			}
		})
	}
}

func TestLoadBackfillsTimeSyncForLegacyConfig(t *testing.T) {
	legacy := loadTempConfig(t, "deployment:\n  mode: standalone\n")
	want := Default().TimeSync
	if !reflect.DeepEqual(legacy.TimeSync, want) {
		t.Fatalf("legacy config time defaults mismatch:\n got: %+v\nwant: %+v", legacy.TimeSync, want)
	}
}

func TestLoadTimeSyncPreservesExplicitDisableAndBackfillsOmittedFields(t *testing.T) {
	cfg := loadTempConfig(t, "time_sync:\n  enabled: false\n")
	if cfg.TimeSync.Enabled {
		t.Fatal("explicit time_sync.enabled=false was overwritten")
	}
	if len(cfg.TimeSync.Sources) == 0 || cfg.TimeSync.SelectionInterval == 0 || cfg.TimeSync.SyncInterval == 0 || cfg.TimeSync.Timeout == 0 {
		t.Fatalf("omitted time sync fields were not backfilled: %+v", cfg.TimeSync)
	}
}

func TestTimeSyncConfigRoundTrip(t *testing.T) {
	want := TimeSyncConfig{
		Enabled:              true,
		Sources:              []string{"ntp1.example.com", "192.0.2.10:123", "[2001:db8::10]:123"},
		SelectionInterval:    36 * time.Hour,
		SyncInterval:         45 * time.Minute,
		Timeout:              1500 * time.Millisecond,
		SamplesPerSource:     5,
		MaxAcceptedOffset:    4 * time.Second,
		MaxRootDispersion:    1500 * time.Millisecond,
		ConsensusTolerance:   200 * time.Millisecond,
	}

	t.Run("yaml", func(t *testing.T) {
		cfg := Default()
		cfg.TimeSync = want
		path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
		if err := Save(path, &cfg); err != nil {
			t.Fatalf("Save: %v", err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !reflect.DeepEqual(loaded.TimeSync, want) {
			t.Fatalf("YAML round trip mismatch:\n got: %+v\nwant: %+v", loaded.TimeSync, want)
		}
	})

	t.Run("yaml explicitly disabled", func(t *testing.T) {
		cfg := Default()
		cfg.TimeSync.Enabled = false
		path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
		if err := Save(path, &cfg); err != nil {
			t.Fatalf("Save: %v", err)
		}
		loaded, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if loaded.TimeSync.Enabled {
			t.Fatal("explicitly disabled time sync was enabled during YAML round trip")
		}
	})

	t.Run("json", func(t *testing.T) {
		original := Config{TimeSync: want}
		encoded, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !strings.Contains(string(encoded), `"time_sync"`) {
			t.Fatalf("JSON does not contain time_sync field: %s", encoded)
		}
		var decoded Config
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !reflect.DeepEqual(decoded.TimeSync, want) {
			t.Fatalf("JSON round trip mismatch:\n got: %+v\nwant: %+v", decoded.TimeSync, want)
		}
	})
}

func TestCloneTimeSyncConfig(t *testing.T) {
	original := Default()
	cloned, err := Clone(&original)
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if !reflect.DeepEqual(cloned.TimeSync, original.TimeSync) {
		t.Fatalf("cloned time config mismatch:\n got: %+v\nwant: %+v", cloned.TimeSync, original.TimeSync)
	}

	cloned.TimeSync.Sources[0] = "mutated.example.com"
	if original.TimeSync.Sources[0] == "mutated.example.com" {
		t.Fatal("Clone shares the time source slice with the original config")
	}
}

func TestValidateTimeSyncAcceptsBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TimeSyncConfig)
	}{
		{
			name: "minimums",
			mutate: func(cfg *TimeSyncConfig) {
				cfg.SelectionInterval = time.Minute
				cfg.SyncInterval = time.Minute
				cfg.Timeout = 100 * time.Millisecond
				cfg.SamplesPerSource = 1
				cfg.MaxAcceptedOffset = time.Nanosecond
				cfg.MaxRootDispersion = time.Nanosecond
				cfg.ConsensusTolerance = time.Nanosecond
			},
		},
		{
			name: "maximums",
			mutate: func(cfg *TimeSyncConfig) {
				cfg.SelectionInterval = 7 * 24 * time.Hour
				cfg.SyncInterval = 24 * time.Hour
				cfg.Timeout = 30 * time.Second
				cfg.SamplesPerSource = 16
				cfg.MaxAcceptedOffset = 10 * time.Minute
				cfg.MaxRootDispersion = time.Minute
				cfg.ConsensusTolerance = 10 * time.Second
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.TimeSync.Sources = []string{"ntp.example.com", "192.0.2.1:123", "[2001:db8::1]:123"}
			tc.mutate(&cfg.TimeSync)
			if err := Validate(&cfg); err != nil {
				t.Fatalf("boundary config should validate: %v", err)
			}
		})
	}
}

func TestValidateTimeSyncRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TimeSyncConfig)
		wantErr string
	}{
		{"too few sources", func(cfg *TimeSyncConfig) { cfg.Sources = cfg.Sources[:2] }, "time_sync.sources must contain between 3 and 64"},
		{"too many sources", func(cfg *TimeSyncConfig) {
			cfg.Sources = make([]string, 65)
			for i := range cfg.Sources {
				cfg.Sources[i] = fmt.Sprintf("ntp-%d.example.com", i)
			}
		}, "time_sync.sources must contain between 3 and 64"},
		{"empty source", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "" }, "time_sync.sources[0] is invalid"},
		{"source with whitespace", func(cfg *TimeSyncConfig) { cfg.Sources[0] = " ntp.example.com" }, "must not contain surrounding whitespace"},
		{"source URL", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "ntp://ntp.example.com" }, "must be a hostname or IP address"},
		{"invalid hostname", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "bad_host.example" }, "must be a hostname or IP address"},
		{"invalid port", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "ntp.example.com:0" }, "port must be between 1 and 65535"},
		{"non-numeric port", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "ntp.example.com:ntp" }, "port must be a number between 1 and 65535"},
		{"port too large", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "ntp.example.com:65536" }, "port must be between 1 and 65535"},
		{"private source", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "10.0.0.1" }, "must not be a private, loopback, link-local, or unspecified address"},
		{"loopback source", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "127.0.0.1:123" }, "must not be a private, loopback, link-local, or unspecified address"},
		{"localhost source", func(cfg *TimeSyncConfig) { cfg.Sources[0] = "localhost" }, "must not be a private, loopback, link-local, or unspecified address"},
		{"duplicate source", func(cfg *TimeSyncConfig) { cfg.Sources = []string{"NTP.EXAMPLE.COM", "ntp.example.com.", "other.example.com"} }, "duplicates source"},
		{"duplicate default port", func(cfg *TimeSyncConfig) { cfg.Sources = []string{"ntp.example.com", "ntp.example.com:123", "other.example.com"} }, "duplicates source"},
		{"selection interval too short", func(cfg *TimeSyncConfig) { cfg.SelectionInterval = time.Minute - time.Nanosecond }, "time_sync.selection_interval must be between 1m and 168h"},
		{"selection interval too long", func(cfg *TimeSyncConfig) { cfg.SelectionInterval = 7*24*time.Hour + time.Nanosecond }, "time_sync.selection_interval must be between 1m and 168h"},
		{"sync interval too short", func(cfg *TimeSyncConfig) { cfg.SyncInterval = time.Minute - time.Nanosecond }, "time_sync.sync_interval must be between 1m and 24h"},
		{"sync interval too long", func(cfg *TimeSyncConfig) { cfg.SyncInterval = 24*time.Hour + time.Nanosecond }, "time_sync.sync_interval must be between 1m and 24h"},
		{"timeout too short", func(cfg *TimeSyncConfig) { cfg.Timeout = 100*time.Millisecond - time.Nanosecond }, "time_sync.timeout must be between 100ms and 30s"},
		{"timeout too long", func(cfg *TimeSyncConfig) { cfg.Timeout = 30*time.Second + time.Nanosecond }, "time_sync.timeout must be between 100ms and 30s"},
		{"no samples", func(cfg *TimeSyncConfig) { cfg.SamplesPerSource = 0 }, "time_sync.samples_per_source must be between 1 and 16"},
		{"too many samples", func(cfg *TimeSyncConfig) { cfg.SamplesPerSource = 17 }, "time_sync.samples_per_source must be between 1 and 16"},
		{"sync slower than selection", func(cfg *TimeSyncConfig) {
			cfg.SelectionInterval = time.Hour
			cfg.SyncInterval = 2 * time.Hour
		}, "time_sync.sync_interval must not exceed time_sync.selection_interval"},
		{"zero accepted offset", func(cfg *TimeSyncConfig) { cfg.MaxAcceptedOffset = 0 }, "time_sync.max_accepted_offset must be positive and at most 10m"},
		{"accepted offset too large", func(cfg *TimeSyncConfig) { cfg.MaxAcceptedOffset = 10*time.Minute + time.Nanosecond }, "time_sync.max_accepted_offset must be positive and at most 10m"},
		{"zero root dispersion", func(cfg *TimeSyncConfig) { cfg.MaxRootDispersion = 0 }, "time_sync.max_root_dispersion must be positive and at most 1m"},
		{"root dispersion too large", func(cfg *TimeSyncConfig) { cfg.MaxRootDispersion = time.Minute + time.Nanosecond }, "time_sync.max_root_dispersion must be positive and at most 1m"},
		{"zero consensus tolerance", func(cfg *TimeSyncConfig) { cfg.ConsensusTolerance = 0 }, "time_sync.consensus_tolerance must be positive and at most 10s"},
		{"consensus tolerance too large", func(cfg *TimeSyncConfig) { cfg.ConsensusTolerance = 10*time.Second + time.Nanosecond }, "time_sync.consensus_tolerance must be positive and at most 10s"},
		{"consensus exceeds accepted offset", func(cfg *TimeSyncConfig) {
			cfg.MaxAcceptedOffset = 100 * time.Millisecond
			cfg.ConsensusTolerance = 200 * time.Millisecond
		}, "time_sync.consensus_tolerance must not exceed time_sync.max_accepted_offset"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.TimeSync.Sources = []string{"ntp-1.example.com", "ntp-2.example.com", "ntp-3.example.com"}
			tc.mutate(&cfg.TimeSync)
			err := Validate(&cfg)
			if err == nil {
				t.Fatalf("expected validation error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validation error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}
