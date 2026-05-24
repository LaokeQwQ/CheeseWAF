package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

func Default() Config {
	return Config{
		Server: ServerConfig{
			Listen:       ":8080",
			ListenTLS:    "",
			AdminListen:  "127.0.0.1:9443",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		TLS: TLSConfig{
			MinVersion: "1.3",
			HSTS:       true,
		},
		Setup: SetupConfig{
			DataDir:         "./data",
			RuntimeDir:      "./data/run",
			ThreeEndUnified: true,
		},
		Sites: []SiteConfig{
			{
				ID:          "default",
				Name:        "default",
				Domains:     []string{"localhost", "127.0.0.1"},
				Upstreams:   []UpstreamConfig{{Address: "127.0.0.1:9000", Weight: 1}},
				ListenPort:  80,
				LoadBalance: "round_robin",
				Enabled:     true,
				WAF: WAFConfig{
					Enabled: true,
					Mode:    "block",
					SemanticEngines: SemanticEngineSwitches{
						SQL:  true,
						XSS:  true,
						RCE:  true,
						LFI:  true,
						XXE:  true,
						SSRF: true,
					},
					Performance: PerformanceTuningConfig{
						MaxBodyBytes:   8 << 20,
						MaxHeaderBytes: 1 << 20,
						ProxyTimeout:   30 * time.Second,
					},
					Response: ResponseInspectionConfig{
						Enabled:      true,
						MaxBodyBytes: 1 << 20,
						SensitivePatterns: []string{
							`AKIA[0-9A-Z]{16}`,
							`(?i)password\s*[=:]\s*['"]?[^'"\s]+`,
							`(?i)secret[_-]?key\s*[=:]\s*['"]?[^'"\s]+`,
						},
					},
					HealthCheck: HealthCheckConfig{
						Enabled:            true,
						Path:               "/",
						Interval:           30 * time.Second,
						Timeout:            3 * time.Second,
						HealthyThreshold:   2,
						UnhealthyThreshold: 2,
					},
				},
			},
		},
		Protection: ProtectionConfig{
			IP: IPProtectionConfig{
				Whitelist: []string{"127.0.0.1", "::1"},
				Blacklist: []string{},
			},
			RateLimit: RateLimitProtectionConfig{
				Enabled: true,
				Default: RateLimitProfile{Requests: 100, Window: time.Minute, Burst: 20},
			},
			ACL: ACLProtectionConfig{Enabled: true},
		},
		Scheduler: SchedulerConfig{
			Enabled: true,
			Tasks: []ScheduledTaskConfig{
				{ID: "log-cleanup", Name: "Log cleanup", Type: "cleanup", Every: 24 * time.Hour, Target: "./logs", Keep: 14, Enabled: true},
				{ID: "config-backup", Name: "Config backup", Type: "backup", Every: 24 * time.Hour, Target: "./data/backups", Keep: 7, Enabled: false},
			},
		},
		Storage: StorageConfig{
			SQLite: SQLiteConfig{Path: "./data/cheesewaf.db"},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: LogOutputConfig{
				Type: "file",
				File: FileLogConfig{Path: "./logs/access.log", MaxSize: "100MB", MaxBackups: 10},
			},
		},
		AI: AIConfig{Enabled: false, APIBase: "https://api.openai.com/v1", Model: "gpt-4o-mini", Async: true},
		Update: UpdateConfig{
			OTA: OTAConfig{
				Enabled:          false,
				Channel:          "stable",
				CheckInterval:    6 * time.Hour,
				AutoUpdateRules:  true,
				AutoUpdateBinary: false,
				VerifySignature:  true,
			},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return &cfg, nil
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(contents, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	applyDefaults(&cfg)
	if err := Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	contents, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	return os.WriteFile(path, contents, 0o640)
}

func Watch(ctx context.Context, path string, interval time.Duration, onChange func(*Config)) error {
	if interval <= 0 {
		interval = time.Second
	}
	var lastMod time.Time
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.ModTime().After(lastMod) {
				lastMod = info.ModTime()
				cfg, err := Load(path)
				if err == nil && onChange != nil {
					onChange(cfg)
				}
			}
		}
	}
}

func applyDefaults(cfg *Config) {
	def := Default()
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = def.Server.Listen
	}
	if cfg.Server.AdminListen == "" {
		cfg.Server.AdminListen = def.Server.AdminListen
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = def.Server.ReadTimeout
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = def.Server.WriteTimeout
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = def.Server.IdleTimeout
	}
	if cfg.Setup.DataDir == "" {
		cfg.Setup.DataDir = def.Setup.DataDir
	}
	if cfg.Setup.RuntimeDir == "" {
		cfg.Setup.RuntimeDir = filepath.Join(cfg.Setup.DataDir, "run")
	}
	if cfg.Storage.SQLite.Path == "" {
		cfg.Storage.SQLite.Path = filepath.Join(cfg.Setup.DataDir, "cheesewaf.db")
	}
	if cfg.Logging.Output.Type == "" {
		cfg.Logging.Output.Type = "file"
	}
	if cfg.Logging.Output.File.Path == "" {
		cfg.Logging.Output.File.Path = "./logs/access.log"
	}
	if len(cfg.Sites) == 0 {
		cfg.Sites = def.Sites
	}
	for idx := range cfg.Sites {
		site := &cfg.Sites[idx]
		if site.ID == "" {
			site.ID = site.Name
		}
		if site.LoadBalance == "" {
			site.LoadBalance = "round_robin"
		}
		if site.ListenPort == 0 {
			site.ListenPort = 80
		}
		if site.WAF.Mode == "" {
			site.WAF.Mode = "block"
		}
		if site.WAF.Performance.MaxBodyBytes == 0 {
			site.WAF.Performance.MaxBodyBytes = 8 << 20
		}
		if site.WAF.Performance.ProxyTimeout == 0 {
			site.WAF.Performance.ProxyTimeout = 30 * time.Second
		}
		if site.WAF.Response.MaxBodyBytes == 0 {
			site.WAF.Response.MaxBodyBytes = 1 << 20
		}
		if site.WAF.HealthCheck.Path == "" {
			site.WAF.HealthCheck.Path = "/"
		}
		if site.WAF.HealthCheck.Interval == 0 {
			site.WAF.HealthCheck.Interval = 30 * time.Second
		}
		if site.WAF.HealthCheck.Timeout == 0 {
			site.WAF.HealthCheck.Timeout = 3 * time.Second
		}
		if site.WAF.HealthCheck.HealthyThreshold == 0 {
			site.WAF.HealthCheck.HealthyThreshold = 2
		}
		if site.WAF.HealthCheck.UnhealthyThreshold == 0 {
			site.WAF.HealthCheck.UnhealthyThreshold = 2
		}
	}
}
