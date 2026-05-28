package config

import (
	"context"
	"fmt"
	"net/http"
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
			ListenHTTP3:  "",
			AdminListen:  "127.0.0.1:9443",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
			HTTP3:        HTTP3Config{Enabled: false, ZeroRTT: false},
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
				Tags:      map[string][]string{},
			},
			RateLimit: RateLimitProtectionConfig{
				Enabled: true,
				Default: RateLimitProfile{Requests: 100, Window: time.Minute, Burst: 20},
			},
			Bot: BotProtectionConfig{
				Enabled:              false,
				JSChallenge:          true,
				CAPTCHA:              false,
				ChallengeTTL:         30 * time.Minute,
				CookieName:           "cheesewaf_js_clearance",
				Secret:               "change-me-in-production",
				PathPrefixes:         []string{"/"},
				ExemptPathPrefixes:   []string{"/health", "/api/"},
				SuspiciousUserAgents: []string{"curl", "python-requests", "sqlmap", "nikto", "nuclei", "masscan", "zgrab", "httpclient"},
			},
			ACL: ACLProtectionConfig{Enabled: true},
		},
		Scheduler: SchedulerConfig{
			Enabled: true,
			Tasks: []ScheduledTaskConfig{
				{ID: "log-cleanup", Name: "Log cleanup", Type: "cleanup", Every: 24 * time.Hour, Target: "./logs", Keep: 14, Enabled: true},
				{ID: "config-backup", Name: "Config backup", Type: "backup", Every: 24 * time.Hour, Target: "./data/backups", Keep: 7, Enabled: false},
				{ID: "security-daily-report", Name: "Security daily report", Type: "security_report", Frequency: "daily", At: "08:00", Channel: "file", Recipient: "./data/reports", Period: "daily", Format: "markdown", Enabled: false},
			},
		},
		Edge: EdgeConfig{
			Headers: HeaderPolicyConfig{
				Enabled: true,
				Rules: []HeaderRuleConfig{
					{ID: "add-request-id", Name: "Add request marker", Operation: "set", Header: "X-CheeseWAF", Value: "edge", Enabled: true},
				},
			},
			Cache: CachePolicyConfig{
				Enabled:      true,
				Mode:         "public",
				TTL:          5 * time.Minute,
				StatusCodes:  []int{http.StatusOK, http.StatusNotModified},
				PathPrefixes: []string{"/assets/", "/static/"},
				MaxBodyBytes: 2 << 20,
			},
			Compression: CompressionPolicyConfig{
				Enabled:      true,
				Algorithms:   []string{"gzip"},
				Level:        5,
				MinBytes:     1024,
				ContentTypes: []string{"text/", "application/json", "application/javascript", "application/xml", "image/svg+xml"},
			},
		},
		Storage: StorageConfig{
			SQLite:       SQLiteConfig{Path: "./data/cheesewaf.db"},
			ClickHouse:   ClickHouseConfig{Database: "default", Table: "cheesewaf_logs", Timeout: 10 * time.Second},
			VictoriaLogs: VictoriaLogsConfig{Timeout: 10 * time.Second},
			PostgreSQL:   PostgreSQLConfig{Table: "cheesewaf_logs", Timeout: 10 * time.Second},
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
		Monitor: MonitorConfig{
			Prometheus:  PrometheusConfig{Enabled: true, Path: "/metrics"},
			RemoteWrite: RemoteWriteConfig{Enabled: false, Interval: 30 * time.Second, Timeout: 10 * time.Second},
			Alerts: AlertEngineConfig{
				Enabled: true,
				Rules: []AlertRuleConfig{
					{ID: "high-block-rate", Name: "High block rate", Metric: "cheesewaf_blocked_total", Operator: ">", Threshold: 100, For: 5 * time.Minute, Severity: "high", Enabled: true},
					{ID: "disk-usage", Name: "Disk usage high", Metric: "cheesewaf_disk_usage_percent", Operator: ">", Threshold: 85, For: 10 * time.Minute, Severity: "medium", Enabled: true},
				},
			},
			Notifiers: []NotifierConfig{
				{ID: "default-webhook", Name: "Default webhook", Type: "webhook", Enabled: false},
			},
		},
		APISec: APISecConfig{
			Enabled: true,
			Discovery: APIDiscoveryConfig{
				Enabled:        true,
				SampleLimit:    500,
				Window:         time.Hour,
				IgnorePrefixes: []string{"/assets/", "/static/", "/favicon"},
			},
			Validation: APIValidationConfig{Enabled: true},
			Auth:       APIAuthConfig{Enabled: false},
			Permissions: map[string][]string{
				"admin":    []string{"*"},
				"readonly": []string{"read:*"},
			},
			Audit: AuditConfig{Enabled: true, Path: "./logs/audit.log"},
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
	if cfg.Storage.ClickHouse.Table == "" {
		cfg.Storage.ClickHouse.Table = def.Storage.ClickHouse.Table
	}
	if cfg.Storage.ClickHouse.Database == "" {
		cfg.Storage.ClickHouse.Database = def.Storage.ClickHouse.Database
	}
	if cfg.Storage.ClickHouse.Timeout == 0 {
		cfg.Storage.ClickHouse.Timeout = def.Storage.ClickHouse.Timeout
	}
	if cfg.Storage.VictoriaLogs.Timeout == 0 {
		cfg.Storage.VictoriaLogs.Timeout = def.Storage.VictoriaLogs.Timeout
	}
	if cfg.Storage.PostgreSQL.Table == "" {
		cfg.Storage.PostgreSQL.Table = def.Storage.PostgreSQL.Table
	}
	if cfg.Storage.PostgreSQL.Timeout == 0 {
		cfg.Storage.PostgreSQL.Timeout = def.Storage.PostgreSQL.Timeout
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
	if cfg.Monitor.Prometheus.Path == "" {
		cfg.Monitor.Prometheus.Path = def.Monitor.Prometheus.Path
	}
	if cfg.Monitor.RemoteWrite.Interval == 0 {
		cfg.Monitor.RemoteWrite.Interval = def.Monitor.RemoteWrite.Interval
	}
	if cfg.Monitor.RemoteWrite.Timeout == 0 {
		cfg.Monitor.RemoteWrite.Timeout = def.Monitor.RemoteWrite.Timeout
	}
	if cfg.APISec.Discovery.SampleLimit == 0 {
		cfg.APISec.Discovery.SampleLimit = def.APISec.Discovery.SampleLimit
	}
	if cfg.APISec.Discovery.Window == 0 {
		cfg.APISec.Discovery.Window = def.APISec.Discovery.Window
	}
	if len(cfg.APISec.Discovery.IgnorePrefixes) == 0 {
		cfg.APISec.Discovery.IgnorePrefixes = def.APISec.Discovery.IgnorePrefixes
	}
	if cfg.APISec.Permissions == nil {
		cfg.APISec.Permissions = def.APISec.Permissions
	}
	if cfg.APISec.Audit.Path == "" {
		cfg.APISec.Audit.Path = def.APISec.Audit.Path
	}
	if cfg.Protection.IP.Tags == nil {
		cfg.Protection.IP.Tags = map[string][]string{}
	}
	if cfg.Protection.Bot.ChallengeTTL == 0 {
		cfg.Protection.Bot.ChallengeTTL = def.Protection.Bot.ChallengeTTL
	}
	if cfg.Protection.Bot.CookieName == "" {
		cfg.Protection.Bot.CookieName = def.Protection.Bot.CookieName
	}
	if cfg.Protection.Bot.Secret == "" {
		cfg.Protection.Bot.Secret = def.Protection.Bot.Secret
	}
	if len(cfg.Protection.Bot.PathPrefixes) == 0 {
		cfg.Protection.Bot.PathPrefixes = def.Protection.Bot.PathPrefixes
	}
	if len(cfg.Protection.Bot.ExemptPathPrefixes) == 0 {
		cfg.Protection.Bot.ExemptPathPrefixes = def.Protection.Bot.ExemptPathPrefixes
	}
	if len(cfg.Protection.Bot.SuspiciousUserAgents) == 0 {
		cfg.Protection.Bot.SuspiciousUserAgents = def.Protection.Bot.SuspiciousUserAgents
	}
	if cfg.Edge.Cache.TTL == 0 {
		cfg.Edge.Cache.TTL = def.Edge.Cache.TTL
	}
	if cfg.Edge.Cache.MaxBodyBytes == 0 {
		cfg.Edge.Cache.MaxBodyBytes = def.Edge.Cache.MaxBodyBytes
	}
	if len(cfg.Edge.Cache.StatusCodes) == 0 {
		cfg.Edge.Cache.StatusCodes = def.Edge.Cache.StatusCodes
	}
	if cfg.Edge.Cache.Mode == "" {
		cfg.Edge.Cache.Mode = "public"
	}
	if cfg.Edge.Compression.Level == 0 {
		cfg.Edge.Compression.Level = def.Edge.Compression.Level
	}
	if cfg.Edge.Compression.MinBytes == 0 {
		cfg.Edge.Compression.MinBytes = def.Edge.Compression.MinBytes
	}
	if len(cfg.Edge.Compression.Algorithms) == 0 {
		cfg.Edge.Compression.Algorithms = def.Edge.Compression.Algorithms
	}
	if len(cfg.Edge.Compression.ContentTypes) == 0 {
		cfg.Edge.Compression.ContentTypes = def.Edge.Compression.ContentTypes
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
