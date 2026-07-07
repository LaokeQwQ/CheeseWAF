package config

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

const AdminSessionTTL = 24 * time.Hour

func Default() Config {
	return Config{
		Deployment: DeploymentConfig{Mode: "standalone"},
		Server: ServerConfig{
			Listen:       ":8080",
			ListenTLS:    "",
			ListenHTTP3:  "",
			AdminListen:  "127.0.0.1:9443",
			AdminPublic:  false,
			AdminTLS:     AdminTLSConfig{Enabled: false, SelfSigned: true},
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
		Cluster: ClusterConfig{
			Enabled: false,
			HAMode:  "single-node",
			Interconnect: InterconnectConfig{
				Listen:       "127.0.0.1:9444",
				MTLSRequired: true,
			},
			Consensus: ConsensusConfig{Provider: "builtin"},
			Join: JoinConfig{
				RequireApproval: true,
				TokenTTL:        15 * time.Minute,
			},
			Protection: ClusterProtectionConfig{
				FreezeWritesWithoutMajority:  true,
				AllowTrafficInProtectionMode: true,
			},
		},
		Console: ConsoleConfig{
			Login: ConsoleLoginConfig{
				CAPTCHA: LoginCAPTCHAConfig{
					Enabled:   true,
					Mode:      "slider",
					MaxNumber: 75000,
					TTL:       2 * time.Minute,
					Slider: LoginSliderCAPTCHAConfig{
						Width:        320,
						Height:       150,
						PieceSize:    42,
						Tolerance:    6,
						MinDrag:      450 * time.Millisecond,
						PowEnabled:   false,
						PowMaxNumber: 12000,
					},
				},
				SecurityEntry: LoginSecurityEntryConfig{
					Enabled:    false,
					Path:       "/__cheesewaf-entry",
					CookieName: "cheesewaf_admin_entry",
				},
				Background: LoginBackgroundConfig{
					Enabled: false,
					Type:    "auto",
				},
			},
			Map: ConsoleMapConfig{
				ChinaBoundary: MapBoundaryConfig{
					Enabled:     false,
					SourceType:  "file",
					License:     "",
					ReviewID:    "",
					Attribution: "",
				},
			},
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
						SQL:   true,
						XSS:   true,
						RCE:   true,
						LFI:   true,
						XXE:   true,
						SSRF:  true,
						NoSQL: true,
						SSTI:  true,
					},
					ProtectionPolicy: ProtectionPolicyConfig{},
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
					AccessControl: SiteAccessControlConfig{
						DynamicGuard: true,
						TrustedCIDRs: []string{},
					},
				},
			},
		},
		Protection: ProtectionConfig{
			Policy: DefaultProtectionPolicy(),
			IP: IPProtectionConfig{
				Whitelist:           []string{"127.0.0.1", "::1"},
				Blacklist:           []string{},
				AccessRules:         []IPAccessRuleConfig{},
				ReputationOverrides: map[string]int{},
				Tags:                map[string][]string{},
			},
			RateLimit: RateLimitProtectionConfig{
				Enabled: true,
				Default: RateLimitProfile{Requests: 100, Window: time.Minute, Burst: 20},
			},
			Bot: BotProtectionConfig{
				Enabled:                    false,
				JSChallenge:                true,
				CAPTCHA:                    false,
				CAPTCHAType:                "pow",
				CAPTCHAMaxAttempts:         5,
				ImageCAPTCHALength:         6,
				ImageCAPTCHAWidth:          220,
				ImageCAPTCHAHeight:         86,
				ImageCAPTCHAAudioLimit:     6,
				SliderCAPTCHAWidth:         320,
				SliderCAPTCHAHeight:        150,
				SliderCAPTCHAPiece:         42,
				SliderCAPTCHATolerance:     6,
				SliderCAPTCHAMinDrag:       450 * time.Millisecond,
				SliderCAPTCHATrackRequired: true,
				CAPTCHAMobileType:          "pow",
				ChallengeDifficulty:        4,
				AltchaMaxNumber:            75000,
				AltchaHeaderName:           "X-CheeseWAF-Altcha",
				WaitingRoom:                false,
				WaitingRoomMaxActive:       1000,
				WaitingRoomTTL:             5 * time.Minute,
				ChallengeTTL:               30 * time.Minute,
				CookieName:                 "cheesewaf_js_clearance",
				Secret:                     "",
				PathPrefixes:               []string{"/"},
				ExemptPathPrefixes:         []string{"/health", "/api/"},
				SuspiciousUserAgents:       []string{"curl", "python-requests", "sqlmap", "nikto", "nuclei", "masscan", "zgrab", "httpclient"},
			},
			ACL: ACLProtectionConfig{Enabled: true},
		},
		Scheduler: SchedulerConfig{
			Enabled: true,
			Tasks: []ScheduledTaskConfig{
				{ID: "log-cleanup", Name: "Log cleanup", Type: "cleanup", Every: 24 * time.Hour, Target: "./logs", Keep: 14, Enabled: true},
				{ID: "config-backup", Name: "Config backup", Type: "backup", Every: 24 * time.Hour, Target: "./data/backups", Keep: 7, Enabled: false},
				{ID: "security-daily-report", Name: "Security daily report", Type: "security_report", Frequency: "daily", At: "08:00", Channel: "file", Recipient: "./data/reports", Period: "daily", Format: "markdown", Enabled: false},
				{ID: "ai-self-learning-rules", Name: "AI self-learning rule review", Type: "ai_self_learning", Frequency: "daily", At: "03:30", Period: "daily", Enabled: false},
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
				Algorithms:   []string{"br", "gzip"},
				Level:        5,
				MinBytes:     1024,
				ContentTypes: []string{"text/", "application/json", "application/javascript", "application/xml", "image/svg+xml"},
			},
		},
		Storage: StorageConfig{
			SQLite:        SQLiteConfig{Path: "./data/cheesewaf.db"},
			ClickHouse:    ClickHouseConfig{Database: "default", Table: "cheesewaf_logs", Timeout: 10 * time.Second},
			VictoriaLogs:  VictoriaLogsConfig{Timeout: 10 * time.Second},
			PostgreSQL:    PostgreSQLConfig{Table: "cheesewaf_logs", Timeout: 10 * time.Second},
			Elasticsearch: ElasticsearchConfig{Index: "cheesewaf-logs", Timeout: 10 * time.Second},
		},
		ACME: ACMEConfig{
			Enabled:       false,
			ACMESHPath:    "acme.sh",
			Home:          "./data/acme",
			Server:        "letsencrypt",
			AccountEmail:  "",
			CertDir:       "./data/certs",
			KeyType:       "ec-256",
			ReloadCommand: "",
			DNSProviders:  []ACMEDNSProviderConfig{},
			Notify:        true,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: LogOutputConfig{
				Type: "file",
				File: FileLogConfig{Path: "./logs/access.log", MaxSize: "100MB", MaxBackups: 10},
			},
		},
		AI: AIConfig{
			Enabled:             false,
			Provider:            "openai",
			APIBase:             "https://api.openai.com/v1",
			APIKeyHeader:        "authorization",
			Model:               "gpt-4o-mini",
			Async:               true,
			AllowPrivateAPIBase: false,
			Assistant:           AIModelConfig{},
			Reasoning:           AIModelConfig{},
			SelfLearning: AISelfLearningConfig{
				Enabled:        false,
				AutoApply:      false,
				DryRun:         true,
				Interval:       24 * time.Hour,
				At:             "03:30",
				MinConfidence:  0.995,
				MinEvents:      5,
				MaxEvents:      200,
				MaxRulesPerRun: 3,
				Action:         "block",
			},
			Knowledge: AIKnowledgeConfig{
				Enabled:     true,
				Builtin:     true,
				MaxSnippets: 5,
			},
		},
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
			Prometheus:  PrometheusConfig{Enabled: true, Path: "/metrics", Public: false},
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
			Auth:       APIAuthConfig{Enabled: false, JWKSRefresh: time.Hour},
			Permissions: map[string][]string{
				"admin":    []string{"*"},
				"readonly": []string{"read:*", "read:cluster"},
			},
			Audit: AuditConfig{Enabled: true, Path: "./logs/audit.log"},
		},
		BlockPage: BlockPageConfig{
			TemplateID: "minimal",
		},
	}
}

const MaxConfigFileBytes = 16 * 1024 * 1024 // 16MB to prevent YAML bomb attacks

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return &cfg, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat config %s: %w", path, err)
	}
	if info.Size() > MaxConfigFileBytes {
		return nil, fmt.Errorf("config file %s exceeds max size (%d bytes > %d bytes)", path, info.Size(), MaxConfigFileBytes)
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
	return writeFileAtomic(path, contents, 0o640)
}

func writeFileAtomic(path string, contents []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return fmt.Errorf("config path %s is a directory", path)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat config path: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	backupName := ""
	if runtime.GOOS == "windows" {
		var err error
		backupName, err = moveExistingFileAside(path, dir)
		if err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		if backupName != "" {
			_ = os.Rename(backupName, path)
		}
		return fmt.Errorf("replace config: %w", err)
	}
	cleanup = false
	if backupName != "" {
		_ = os.Remove(backupName)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func moveExistingFileAside(path, dir string) (string, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat existing config: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("config path %s is a directory", path)
	}
	backup, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.bak")
	if err != nil {
		return "", fmt.Errorf("create config backup placeholder: %w", err)
	}
	backupName := backup.Name()
	if err := backup.Close(); err != nil {
		_ = os.Remove(backupName)
		return "", fmt.Errorf("close config backup placeholder: %w", err)
	}
	if err := os.Remove(backupName); err != nil {
		return "", fmt.Errorf("remove config backup placeholder: %w", err)
	}
	if err := os.Rename(path, backupName); err != nil {
		return "", fmt.Errorf("move existing config aside: %w", err)
	}
	return backupName, nil
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
	if cfg.Deployment.Mode == "" {
		cfg.Deployment.Mode = def.Deployment.Mode
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = def.Server.Listen
	}
	if cfg.Server.AdminListen == "" {
		cfg.Server.AdminListen = def.Server.AdminListen
	}
	if cfg.Server.AdminTLS.SelfSigned == false && cfg.Server.AdminTLS.CertFile == "" && cfg.Server.AdminTLS.KeyFile == "" && !cfg.Server.AdminTLS.Enabled {
		cfg.Server.AdminTLS.SelfSigned = def.Server.AdminTLS.SelfSigned
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
	if cfg.Cluster.HAMode == "" {
		cfg.Cluster.HAMode = def.Cluster.HAMode
	}
	if cfg.Cluster.Interconnect.Listen == "" {
		cfg.Cluster.Interconnect.Listen = def.Cluster.Interconnect.Listen
	}
	if cfg.Cluster.Consensus.Provider == "" {
		cfg.Cluster.Consensus.Provider = def.Cluster.Consensus.Provider
	}
	if cfg.Cluster.Join.TokenTTL == 0 {
		cfg.Cluster.Join.TokenTTL = def.Cluster.Join.TokenTTL
	}
	if cfg.Console.Login.CAPTCHA.MaxNumber == 0 {
		cfg.Console.Login.CAPTCHA.MaxNumber = def.Console.Login.CAPTCHA.MaxNumber
	}
	if cfg.Console.Login.CAPTCHA.Mode == "" {
		cfg.Console.Login.CAPTCHA.Mode = def.Console.Login.CAPTCHA.Mode
	}
	if cfg.Console.Login.CAPTCHA.TTL == 0 {
		cfg.Console.Login.CAPTCHA.TTL = def.Console.Login.CAPTCHA.TTL
	}
	if cfg.Console.Login.CAPTCHA.Slider.Width == 0 {
		cfg.Console.Login.CAPTCHA.Slider.Width = def.Console.Login.CAPTCHA.Slider.Width
	}
	if cfg.Console.Login.CAPTCHA.Slider.Height == 0 {
		cfg.Console.Login.CAPTCHA.Slider.Height = def.Console.Login.CAPTCHA.Slider.Height
	}
	if cfg.Console.Login.CAPTCHA.Slider.PieceSize == 0 {
		cfg.Console.Login.CAPTCHA.Slider.PieceSize = def.Console.Login.CAPTCHA.Slider.PieceSize
	}
	if cfg.Console.Login.CAPTCHA.Slider.Tolerance == 0 {
		cfg.Console.Login.CAPTCHA.Slider.Tolerance = def.Console.Login.CAPTCHA.Slider.Tolerance
	}
	if cfg.Console.Login.CAPTCHA.Slider.MinDrag == 0 {
		cfg.Console.Login.CAPTCHA.Slider.MinDrag = def.Console.Login.CAPTCHA.Slider.MinDrag
	}
	if cfg.Console.Login.CAPTCHA.Slider.PowMaxNumber == 0 {
		cfg.Console.Login.CAPTCHA.Slider.PowMaxNumber = def.Console.Login.CAPTCHA.Slider.PowMaxNumber
	}
	if cfg.Console.Login.SecurityEntry.Path == "" {
		cfg.Console.Login.SecurityEntry.Path = def.Console.Login.SecurityEntry.Path
	}
	if cfg.Console.Login.SecurityEntry.CookieName == "" {
		cfg.Console.Login.SecurityEntry.CookieName = def.Console.Login.SecurityEntry.CookieName
	}
	if cfg.Console.Login.Background.Type == "" {
		cfg.Console.Login.Background.Type = def.Console.Login.Background.Type
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
	if cfg.Storage.Elasticsearch.Index == "" {
		cfg.Storage.Elasticsearch.Index = def.Storage.Elasticsearch.Index
	}
	if cfg.Storage.Elasticsearch.Timeout == 0 {
		cfg.Storage.Elasticsearch.Timeout = def.Storage.Elasticsearch.Timeout
	}
	if cfg.Storage.Elasticsearch.Headers == nil {
		cfg.Storage.Elasticsearch.Headers = map[string]string{}
	}
	if cfg.ACME.ACMESHPath == "" {
		cfg.ACME.ACMESHPath = def.ACME.ACMESHPath
	}
	if cfg.ACME.Home == "" {
		cfg.ACME.Home = def.ACME.Home
	}
	if cfg.ACME.Server == "" {
		cfg.ACME.Server = def.ACME.Server
	}
	if cfg.ACME.CertDir == "" {
		cfg.ACME.CertDir = def.ACME.CertDir
	}
	if cfg.ACME.KeyType == "" {
		cfg.ACME.KeyType = def.ACME.KeyType
	}
	if cfg.Logging.Output.Type == "" {
		cfg.Logging.Output.Type = "file"
	}
	if cfg.Logging.Output.File.Path == "" {
		cfg.Logging.Output.File.Path = "./logs/access.log"
	}
	if cfg.AI.Provider == "" {
		cfg.AI.Provider = def.AI.Provider
	}
	if cfg.AI.APIBase == "" {
		switch cfg.AI.Provider {
		case "anthropic":
			cfg.AI.APIBase = "https://api.anthropic.com/v1"
		default:
			cfg.AI.APIBase = def.AI.APIBase
		}
	}
	if cfg.AI.APIKeyHeader == "" {
		cfg.AI.APIKeyHeader = def.AI.APIKeyHeader
	}
	if cfg.AI.Model == "" {
		switch cfg.AI.Provider {
		case "anthropic":
			cfg.AI.Model = "claude-3-5-haiku-latest"
		default:
			cfg.AI.Model = def.AI.Model
		}
	}
	applyAIModelDefaults(&cfg.AI.Assistant, cfg.AI.RuntimeModelConfig())
	assistantRuntime := cfg.AI.AssistantRuntimeConfig().RuntimeModelConfig()
	applyAIModelDefaults(&cfg.AI.Reasoning, assistantRuntime)
	if cfg.AI.SelfLearning.Interval == 0 {
		cfg.AI.SelfLearning.Interval = def.AI.SelfLearning.Interval
	}
	if cfg.AI.SelfLearning.At == "" {
		cfg.AI.SelfLearning.At = def.AI.SelfLearning.At
	}
	if cfg.AI.SelfLearning.MinConfidence == 0 {
		cfg.AI.SelfLearning.MinConfidence = def.AI.SelfLearning.MinConfidence
	}
	if cfg.AI.SelfLearning.MinEvents == 0 {
		cfg.AI.SelfLearning.MinEvents = def.AI.SelfLearning.MinEvents
	}
	if cfg.AI.SelfLearning.MaxEvents == 0 {
		cfg.AI.SelfLearning.MaxEvents = def.AI.SelfLearning.MaxEvents
	}
	if cfg.AI.SelfLearning.MaxRulesPerRun == 0 {
		cfg.AI.SelfLearning.MaxRulesPerRun = def.AI.SelfLearning.MaxRulesPerRun
	}
	if cfg.AI.SelfLearning.Action == "" {
		cfg.AI.SelfLearning.Action = def.AI.SelfLearning.Action
	}
	if cfg.AI.Knowledge.MaxSnippets == 0 {
		cfg.AI.Knowledge.MaxSnippets = def.AI.Knowledge.MaxSnippets
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
	if cfg.APISec.Auth.JWKSRefresh == 0 {
		cfg.APISec.Auth.JWKSRefresh = def.APISec.Auth.JWKSRefresh
	}
	if cfg.BlockPage.TemplateID == "" {
		cfg.BlockPage.TemplateID = def.BlockPage.TemplateID
	}
	if cfg.Protection.IP.Tags == nil {
		cfg.Protection.IP.Tags = map[string][]string{}
	}
	cfg.Protection.Policy = cfg.Protection.Policy.WithDefaults(DefaultProtectionPolicy())
	if cfg.Protection.Bot.ChallengeTTL == 0 {
		cfg.Protection.Bot.ChallengeTTL = def.Protection.Bot.ChallengeTTL
	}
	if cfg.Protection.Bot.ChallengeDifficulty == 0 {
		cfg.Protection.Bot.ChallengeDifficulty = def.Protection.Bot.ChallengeDifficulty
	}
	if cfg.Protection.Bot.AltchaMaxNumber == 0 {
		cfg.Protection.Bot.AltchaMaxNumber = def.Protection.Bot.AltchaMaxNumber
	}
	if cfg.Protection.Bot.AltchaHeaderName == "" {
		cfg.Protection.Bot.AltchaHeaderName = def.Protection.Bot.AltchaHeaderName
	}
	if cfg.Protection.Bot.CAPTCHAType == "" {
		cfg.Protection.Bot.CAPTCHAType = def.Protection.Bot.CAPTCHAType
	}
	if cfg.Protection.Bot.CAPTCHAMaxAttempts == 0 {
		cfg.Protection.Bot.CAPTCHAMaxAttempts = def.Protection.Bot.CAPTCHAMaxAttempts
	}
	if cfg.Protection.Bot.ImageCAPTCHALength == 0 {
		cfg.Protection.Bot.ImageCAPTCHALength = def.Protection.Bot.ImageCAPTCHALength
	}
	if cfg.Protection.Bot.ImageCAPTCHAWidth == 0 {
		cfg.Protection.Bot.ImageCAPTCHAWidth = def.Protection.Bot.ImageCAPTCHAWidth
	}
	if cfg.Protection.Bot.ImageCAPTCHAHeight == 0 {
		cfg.Protection.Bot.ImageCAPTCHAHeight = def.Protection.Bot.ImageCAPTCHAHeight
	}
	if cfg.Protection.Bot.ImageCAPTCHAAudioLimit == 0 {
		cfg.Protection.Bot.ImageCAPTCHAAudioLimit = def.Protection.Bot.ImageCAPTCHAAudioLimit
	}
	if cfg.Protection.Bot.SliderCAPTCHAWidth == 0 {
		cfg.Protection.Bot.SliderCAPTCHAWidth = def.Protection.Bot.SliderCAPTCHAWidth
	}
	if cfg.Protection.Bot.SliderCAPTCHAHeight == 0 {
		cfg.Protection.Bot.SliderCAPTCHAHeight = def.Protection.Bot.SliderCAPTCHAHeight
	}
	if cfg.Protection.Bot.SliderCAPTCHAPiece == 0 {
		cfg.Protection.Bot.SliderCAPTCHAPiece = def.Protection.Bot.SliderCAPTCHAPiece
	}
	if cfg.Protection.Bot.SliderCAPTCHATolerance == 0 {
		cfg.Protection.Bot.SliderCAPTCHATolerance = def.Protection.Bot.SliderCAPTCHATolerance
	}
	if cfg.Protection.Bot.SliderCAPTCHAMinDrag == 0 {
		cfg.Protection.Bot.SliderCAPTCHAMinDrag = def.Protection.Bot.SliderCAPTCHAMinDrag
	}
	if cfg.Protection.Bot.CAPTCHAMobileType == "" {
		cfg.Protection.Bot.CAPTCHAMobileType = def.Protection.Bot.CAPTCHAMobileType
	}
	if cfg.Protection.Bot.WaitingRoomMaxActive == 0 {
		cfg.Protection.Bot.WaitingRoomMaxActive = def.Protection.Bot.WaitingRoomMaxActive
	}
	if cfg.Protection.Bot.WaitingRoomTTL == 0 {
		cfg.Protection.Bot.WaitingRoomTTL = def.Protection.Bot.WaitingRoomTTL
	}
	if cfg.Protection.Bot.CookieName == "" {
		cfg.Protection.Bot.CookieName = def.Protection.Bot.CookieName
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
		if site.Certificate.Mode == "" {
			site.Certificate.Mode = "file"
		}
		if site.Certificate.MinTLSVersion == "" {
			site.Certificate.MinTLSVersion = "1.2"
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

func applyAIModelDefaults(model *AIModelConfig, fallback AIModelConfig) {
	if model == nil {
		return
	}
	if model.Provider == "" {
		model.Provider = fallback.Provider
	}
	if model.APIBase == "" {
		model.APIBase = fallback.APIBase
	}
	if model.APIKey == "" {
		model.APIKey = fallback.APIKey
	}
	if model.APIKeyHeader == "" {
		model.APIKeyHeader = fallback.APIKeyHeader
	}
	if model.Model == "" {
		model.Model = fallback.Model
	}
	model.AllowPrivateAPIBase = model.AllowPrivateAPIBase || fallback.AllowPrivateAPIBase
}
