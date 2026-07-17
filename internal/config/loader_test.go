package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
	if cfg.Console.Login.CAPTCHA.Mode != "slider" || cfg.Console.Login.CAPTCHA.Slider.PowMaxNumber <= 0 {
		t.Fatalf("expected sample login captcha slider defaults, got %+v", cfg.Console.Login.CAPTCHA)
	}
}

func TestValidateSecurityEntryRejectsRouteConflicts(t *testing.T) {
	for _, path := range []string{"/", "/login", "/api", "/api/auth/login", "/health"} {
		cfg := Default()
		cfg.Console.Login.SecurityEntry.Enabled = true
		cfg.Console.Login.SecurityEntry.Path = path
		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected security entry path %q to be rejected", path)
		}
	}
	cfg := Default()
	cfg.Console.Login.SecurityEntry.Enabled = true
	cfg.Console.Login.SecurityEntry.Path = "/secure-admin"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected valid security entry path: %v", err)
	}
}

func TestMoveExistingFileAsidePreservesOriginalForRecovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cheesewaf.yaml")
	original := []byte("server:\n  listen: ':8080'\n")
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatal(err)
	}
	backup, err := moveExistingFileAside(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	if backup == "" {
		t.Fatal("expected backup path")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected original path to be moved aside, got %v", err)
	}
	restored, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatalf("backup content mismatch: %q", string(restored))
	}
	if err := os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	asserted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(asserted) != string(original) {
		t.Fatalf("restored content mismatch: %q", string(asserted))
	}
}

func TestValidateBlockPageCustomHTML(t *testing.T) {
	cfg := Default()
	cfg.BlockPage.CustomEnabled = true
	cfg.BlockPage.CustomHTML = `<html><body>{{.TraceID}}</body></html>`
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected valid custom block page: %v", err)
	}
	cfg.BlockPage.CustomHTML = `<html><body>{{if}}</body></html>`
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected invalid custom block page template to be rejected")
	}
}

func TestValidateAIAPIBaseRejectsPrivateByDefault(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "http://127.0.0.1:11434/v1"
	cfg.AI.APIKey = "secret"
	cfg.AI.Model = "local-model"

	if err := Validate(&cfg); err == nil {
		t.Fatal("expected private ai.api_base to be rejected by default")
	}
}

func TestValidateAIAPIBaseAllowsPrivateWhenExplicit(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "http://127.0.0.1:11434/v1"
	cfg.AI.APIKey = "secret"
	cfg.AI.Model = "local-model"
	cfg.AI.AllowPrivateAPIBase = true

	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected explicit private ai.api_base to validate: %v", err)
	}
}

func TestLoadBackfillsNewSemanticEnginesForOldSiteConfig(t *testing.T) {
	cfg := loadTempConfig(t, `
sites:
  - id: default
    name: default
    domains: ["localhost"]
    upstreams:
      - address: "127.0.0.1:9000"
        weight: 1
    enabled: true
    waf:
      enabled: true
      mode: block
      semantic_engines:
        sql: true
        xss: true
        rce: true
        lfi: true
        xxe: true
        ssrf: true
`)

	engines := cfg.Sites[0].WAF.SemanticEngines
	if !engines.NoSQL || !engines.SSTI {
		t.Fatalf("expected omitted new semantic engines to default on, got %+v", engines)
	}
}

func TestLoadHonorsExplicitSemanticEngineFalse(t *testing.T) {
	cfg := loadTempConfig(t, `
sites:
  - id: default
    name: default
    domains: ["localhost"]
    upstreams:
      - address: "127.0.0.1:9000"
        weight: 1
    enabled: true
    waf:
      enabled: true
      mode: block
      semantic_engines:
        sql: true
        xss: true
        rce: true
        lfi: true
        xxe: true
        ssrf: true
        nosql: false
        ssti: false
`)

	engines := cfg.Sites[0].WAF.SemanticEngines
	if engines.NoSQL || engines.SSTI {
		t.Fatalf("expected explicit disabled semantic engines to stay disabled, got %+v", engines)
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

func loadTempConfig(t *testing.T, raw string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
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

func TestValidatePublicPrometheusPathDoesNotConflictWithProtectedRoutes(t *testing.T) {
	for _, path := range []string{"/api", "/api/metrics", "/health"} {
		cfg := Default()
		cfg.Monitor.Prometheus.Enabled = true
		cfg.Monitor.Prometheus.Public = true
		cfg.Monitor.Prometheus.Path = path

		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected public prometheus path %q to be rejected", path)
		}
	}

	cfg := Default()
	cfg.Monitor.Prometheus.Enabled = true
	cfg.Monitor.Prometheus.Public = true
	cfg.Monitor.Prometheus.Path = "/metrics"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected public prometheus /metrics to validate: %v", err)
	}
}

func TestValidateRemoteWriteEndpointGuard(t *testing.T) {
	for _, rawURL := range []string{
		"http://127.0.0.1:8428/api/v1/write",
		"http://169.254.169.254/latest/meta-data",
		"https://user:pass@metrics.example.com/write",
		"file:///etc/passwd",
	} {
		cfg := Default()
		cfg.Monitor.RemoteWrite.Enabled = true
		cfg.Monitor.RemoteWrite.Endpoint = rawURL

		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected unsafe remote_write endpoint %q to fail validation", rawURL)
		}
	}

	cfg := Default()
	cfg.Monitor.RemoteWrite.Enabled = true
	cfg.Monitor.RemoteWrite.Endpoint = "http://127.0.0.1:8428/api/v1/write"
	cfg.Monitor.RemoteWrite.AllowPrivateEndpoint = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected explicitly allowed private remote_write endpoint to validate: %v", err)
	}
}

func TestValidateOTAEndpointGuard(t *testing.T) {
	for _, rawURL := range []string{
		"http://updates.example.com/releases.json",
		"https://127.0.0.1/releases.json",
		"https://169.254.169.254/latest/meta-data",
		"https://user:pass@updates.example.com/releases.json",
		"https://updates.example.com/releases.json#token",
	} {
		cfg := Default()
		cfg.Update.OTA.Enabled = true
		cfg.Update.OTA.Server = rawURL

		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected unsafe OTA server %q to fail validation", rawURL)
		}
	}

	cfg := Default()
	cfg.Update.OTA.Enabled = true
	cfg.Update.OTA.Server = "https://ota.waf.laoker.cc/"
	cfg.Update.OTA.Channel = "stable"
	cfg.Update.OTA.CheckInterval = 6 * time.Hour
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected public HTTPS OTA server to validate: %v", err)
	}

	cfg.Update.OTA.CheckInterval = 30 * time.Minute
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected too frequent OTA check interval to fail validation")
	}
}

func TestValidateVulnerabilityFeedGuard(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*VulnerabilityFeedConfig)
		wantError string
	}{
		{
			name: "unsafe url",
			mutate: func(feed *VulnerabilityFeedConfig) {
				feed.URL = "http://127.0.0.1/feed.json"
			},
			wantError: "url is invalid",
		},
		{
			name: "short interval",
			mutate: func(feed *VulnerabilityFeedConfig) {
				feed.Interval = 30 * time.Minute
			},
			wantError: "interval",
		},
		{
			name: "bad type",
			mutate: func(feed *VulnerabilityFeedConfig) {
				feed.Type = "shell"
			},
			wantError: "invalid type",
		},
		{
			name: "bad severity",
			mutate: func(feed *VulnerabilityFeedConfig) {
				feed.MinSeverity = "urgent"
			},
			wantError: "invalid min_severity",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			feed := VulnerabilityFeedConfig{
				ID:          "nvd",
				Name:        "NVD",
				Type:        "nvd",
				URL:         "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz",
				Interval:    6 * time.Hour,
				MinSeverity: "medium",
				Enabled:     true,
			}
			tc.mutate(&feed)
			cfg.Vulnerability.Feeds = []VulnerabilityFeedConfig{feed}

			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("expected error containing %q, got %v", tc.wantError, err)
			}
		})
	}

	cfg := Default()
	cfg.Vulnerability.Feeds = []VulnerabilityFeedConfig{{
		ID:          "osv",
		Name:        "OSV",
		Type:        "osv",
		URL:         "https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip",
		Interval:    24 * time.Hour,
		MinSeverity: "low",
		Enabled:     true,
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected public HTTPS vulnerability feed to validate: %v", err)
	}
}

func TestValidateSchedulerTaskGuard(t *testing.T) {
	cfg := Default()
	cfg.Scheduler.Tasks = []ScheduledTaskConfig{{
		Type:    "cleanup",
		Target:  "./logs",
		Enabled: true,
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected legacy cleanup task without id to validate after normalization: %v", err)
	}

	cfg = Default()
	cfg.Scheduler.Tasks = []ScheduledTaskConfig{{
		ID:        "monthly-report",
		Type:      "security_report",
		Frequency: "monthly",
		Period:    "monthly",
		Channel:   "file",
		Recipient: "./data/reports",
		Enabled:   true,
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected monthly security report task to validate: %v", err)
	}

	cfg = Default()
	cfg.Scheduler.Tasks = []ScheduledTaskConfig{{
		ID:        "unsafe-report",
		Type:      "security_report",
		Frequency: "daily",
		Channel:   "webhook",
		Recipient: "http://127.0.0.1:8080/hook",
		Enabled:   true,
	}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected private/insecure security report webhook to fail validation")
	}

	cfg = Default()
	cfg.Scheduler.Tasks = []ScheduledTaskConfig{{
		ID:        "webhook-report",
		Type:      "security_report",
		Frequency: "daily",
		Channel:   "webhook",
		Recipient: "https://hooks.example.com/cheesewaf/report",
		Format:    "json",
		Period:    "weekly",
		Enabled:   true,
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected public HTTPS security report webhook to validate: %v", err)
	}
}

func TestValidateSchedulerRejectsDuplicateTaskIDs(t *testing.T) {
	cfg := Default()
	cfg.Scheduler.Tasks = []ScheduledTaskConfig{
		{ID: "duplicate", Type: "cleanup", Target: "./logs", Enabled: true},
		{ID: "duplicate", Type: "backup", Target: "./data/backups", Enabled: true},
	}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected duplicate scheduler task IDs to fail validation")
	}
}

func TestValidateSchedulerRejectsCleanupOutsideManagedRoots(t *testing.T) {
	cfg := Default()
	cfg.Setup.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Logging.Output.File.Path = filepath.Join(t.TempDir(), "logs", "access.log")
	cfg.Scheduler.Tasks = []ScheduledTaskConfig{{ID: "unsafe", Type: "cleanup", Target: t.TempDir(), Enabled: true}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected cleanup target outside managed roots to fail validation")
	}
}

func TestValidateNotifierEndpointGuard(t *testing.T) {
	for _, rawURL := range []string{
		"http://127.0.0.1:8080/hook",
		"http://100.100.100.200/latest/meta-data",
		"https://user:pass@hooks.example.com/notify",
		"gopher://hooks.example.com/notify",
	} {
		cfg := Default()
		cfg.Monitor.Notifiers = []NotifierConfig{{
			ID:       "webhook",
			Type:     "webhook",
			Endpoint: rawURL,
			Enabled:  true,
		}}

		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected unsafe notifier endpoint %q to fail validation", rawURL)
		}
	}

	cfg := Default()
	cfg.Monitor.Notifiers = []NotifierConfig{{
		ID:                   "webhook",
		Type:                 "webhook",
		Endpoint:             "http://127.0.0.1:8080/hook",
		AllowPrivateEndpoint: true,
		Enabled:              true,
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected explicitly allowed private notifier endpoint to validate: %v", err)
	}
}

func TestValidateMapBoundaryURLGuard(t *testing.T) {
	for _, rawURL := range []string{
		"http://maps.example.com/china-boundary.geojson",
		"https://127.0.0.1/china-boundary.geojson",
		"https://user:pass@maps.example.com/china-boundary.geojson",
		"file:///etc/passwd",
	} {
		cfg := Default()
		cfg.Console.Map.ChinaBoundary = MapBoundaryConfig{
			Enabled:    true,
			SourceType: "url",
			Source:     rawURL,
			License:    "licensed fixture",
			ReviewID:   "GS-test",
		}

		if err := Validate(&cfg); err == nil {
			t.Fatalf("expected unsafe map boundary URL %q to fail validation", rawURL)
		}
	}

	cfg := Default()
	cfg.Console.Map.ChinaBoundary = MapBoundaryConfig{
		Enabled:       true,
		SourceType:    "url",
		Source:        "http://127.0.0.1/china-boundary.geojson",
		License:       "licensed fixture",
		ReviewID:      "GS-test",
		AllowInsecure: true,
		AllowPrivate:  true,
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("expected explicitly allowed private map boundary URL to validate: %v", err)
	}
}

func TestValidateStorageLogSinkEndpointGuard(t *testing.T) {
	tests := []struct {
		name        string
		configure   func(*Config, string, bool)
		unsafeURL   string
		allowedURL  string
		errContains string
	}{
		{
			name: "clickhouse",
			configure: func(cfg *Config, endpoint string, allowPrivate bool) {
				cfg.Storage.ClickHouse.Enabled = true
				cfg.Storage.ClickHouse.Endpoint = endpoint
				cfg.Storage.ClickHouse.AllowPrivateEndpoint = allowPrivate
			},
			unsafeURL:   "http://127.0.0.1:8123",
			allowedURL:  "http://127.0.0.1:8123",
			errContains: "storage.clickhouse.endpoint",
		},
		{
			name: "victorialogs",
			configure: func(cfg *Config, endpoint string, allowPrivate bool) {
				cfg.Storage.VictoriaLogs.Enabled = true
				cfg.Storage.VictoriaLogs.Endpoint = endpoint
				cfg.Storage.VictoriaLogs.AllowPrivateEndpoint = allowPrivate
			},
			unsafeURL:   "http://169.254.169.254/latest/meta-data",
			allowedURL:  "http://127.0.0.1:9428/insert/jsonline",
			errContains: "storage.victorialogs.endpoint",
		},
		{
			name: "elasticsearch",
			configure: func(cfg *Config, endpoint string, allowPrivate bool) {
				cfg.Storage.Elasticsearch.Enabled = true
				cfg.Storage.Elasticsearch.Endpoint = endpoint
				cfg.Storage.Elasticsearch.AllowPrivateEndpoint = allowPrivate
			},
			unsafeURL:   "https://user:pass@es.example.com",
			allowedURL:  "http://127.0.0.1:9200",
			errContains: "storage.elasticsearch.endpoint",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.configure(&cfg, tc.unsafeURL, false)
			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected unsafe endpoint rejected with %q, got %v", tc.errContains, err)
			}

			cfg = Default()
			tc.configure(&cfg, tc.allowedURL, true)
			if err := Validate(&cfg); err != nil {
				t.Fatalf("expected explicitly allowed private endpoint to validate: %v", err)
			}
		})
	}
}

func TestValidateACMEConfigurationGuard(t *testing.T) {
	t.Run("rejects unsafe directory URL", func(t *testing.T) {
		for _, server := range []string{
			"http://acme.example.com/directory",
			"https://127.0.0.1/acme/directory",
			"https://user:pass@acme.example.com/directory",
		} {
			cfg := Default()
			cfg.ACME.Enabled = true
			cfg.ACME.Server = server

			if err := Validate(&cfg); err == nil {
				t.Fatalf("expected unsafe ACME server %q to fail validation", server)
			}
		}
	})

	t.Run("accepts known aliases and public https directory", func(t *testing.T) {
		for _, server := range []string{
			"letsencrypt",
			"zerossl",
			"https://acme-v02.api.letsencrypt.org/directory",
		} {
			cfg := Default()
			cfg.ACME.Enabled = true
			cfg.ACME.Server = server

			if err := Validate(&cfg); err != nil {
				t.Fatalf("expected ACME server %q to validate: %v", server, err)
			}
		}
	})

	t.Run("rejects unsafe dns api and reload command", func(t *testing.T) {
		cfg := Default()
		cfg.ACME.Enabled = true
		cfg.ACME.DNSProviders = []ACMEDNSProviderConfig{{
			ID:      "bad",
			API:     "dns_cf;sh",
			Enabled: true,
		}}

		if err := Validate(&cfg); err == nil {
			t.Fatal("expected unsafe DNS API name to fail validation")
		}

		cfg = Default()
		cfg.ACME.Enabled = true
		cfg.ACME.ReloadCommand = "systemctl reload cheesewaf\ncurl https://example.com"
		if err := Validate(&cfg); err == nil {
			t.Fatal("expected multiline reload command to fail validation")
		}
	})
}

func TestValidateAPISecJWTSignatureConfig(t *testing.T) {
	t.Run("rejects none algorithm", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"none"}
		cfg.APISec.Auth.JWTSharedSecret = "secret"

		if err := Validate(&cfg); err == nil {
			t.Fatal("expected alg none validation error")
		}
	})

	t.Run("requires verification key when algorithms are configured", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}

		if err := Validate(&cfg); err == nil {
			t.Fatal("expected missing JWT verification key validation error")
		}
	})

	t.Run("accepts remote JWKS URL as verification key source", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"RS256"}
		cfg.APISec.Auth.JWKSURL = "https://keys.example.com/.well-known/jwks.json"

		if err := Validate(&cfg); err != nil {
			t.Fatalf("expected remote JWKS auth config to validate: %v", err)
		}
	})

	t.Run("rejects unsafe remote JWKS URL", func(t *testing.T) {
		for _, rawURL := range []string{
			"http://keys.example.com/jwks.json",
			"https://127.0.0.1/jwks.json",
			"https://[::1]/jwks.json",
			"https://user:pass@keys.example.com/jwks.json",
		} {
			cfg := Default()
			cfg.APISec.Auth.Enabled = true
			cfg.APISec.Auth.JWTAlgorithms = []string{"RS256"}
			cfg.APISec.Auth.JWKSURL = rawURL

			if err := Validate(&cfg); err == nil {
				t.Fatalf("expected unsafe remote JWKS URL %q to fail validation", rawURL)
			}
		}
	})

	t.Run("rejects too frequent remote JWKS refresh", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"RS256"}
		cfg.APISec.Auth.JWKSURL = "https://keys.example.com/jwks.json"
		cfg.APISec.Auth.JWKSRefresh = 10 * time.Second

		if err := Validate(&cfg); err == nil {
			t.Fatal("expected too frequent remote JWKS refresh validation error")
		}
	})

	t.Run("accepts signed JWT configuration", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTAlgorithms = []string{"HS256"}
		cfg.APISec.Auth.JWTSharedSecret = "secret"

		if err := Validate(&cfg); err != nil {
			t.Fatalf("expected signed JWT auth config to validate: %v", err)
		}
	})

	t.Run("rejects invalid endpoint policy", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.EndpointPolicies = []APIAuthEndpointPolicyConfig{{
			ID:          "bad",
			Method:      "TRACE",
			PathPattern: "(",
			Enabled:     true,
		}}

		if err := Validate(&cfg); err == nil {
			t.Fatal("expected invalid endpoint auth policy validation error")
		}
	})

	t.Run("accepts endpoint policy audience override", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		cfg.APISec.Auth.JWTSharedSecret = "test-secret"
		cfg.APISec.Auth.EndpointPolicies = []APIAuthEndpointPolicyConfig{{
			ID:             "orders-write",
			Method:         "POST",
			PathPattern:    "^/api/orders$",
			JWTAudiences:   []string{"orders-api"},
			RequiredScopes: []string{"orders:write"},
			Enabled:        true,
		}}

		if err := Validate(&cfg); err != nil {
			t.Fatalf("expected endpoint auth policy to validate: %v", err)
		}
	})

	t.Run("rejects auth enabled without verification material", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.Auth.Enabled = true
		if err := Validate(&cfg); err == nil {
			t.Fatal("expected auth enabled without keys to fail validation")
		}
	})
}

func TestValidatePublicAdminRequiresExplicitTLS(t *testing.T) {
	cfg := Default()
	cfg.Server.AdminListen = "0.0.0.0:9443"

	if err := Validate(&cfg); err == nil {
		t.Fatal("expected public admin listener validation error")
	}

	cfg.Server.AdminPublic = true
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected admin TLS validation error")
	}

	cfg.Server.AdminTLS.Enabled = true
	cfg.Server.AdminTLS.CertFile = "./data/certs/admin.crt"
	cfg.Server.AdminTLS.KeyFile = "./data/certs/admin.key"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("public admin with TLS should validate: %v", err)
	}
}

func TestEnsureRuntimeSecretsRotatesPlaceholder(t *testing.T) {
	cfg := Default()
	cfg.Protection.Bot.Secret = BotSecretPlaceholder
	changed, err := EnsureRuntimeSecrets(&cfg)
	if err != nil {
		t.Fatalf("EnsureRuntimeSecrets() error = %v", err)
	}
	if !changed {
		t.Fatal("expected runtime secret repair")
	}
	if IsWeakBotSecret(cfg.Protection.Bot.Secret) {
		t.Fatalf("expected strong bot secret, got %q", cfg.Protection.Bot.Secret)
	}
}

func TestProtectionPolicyInheritsGlobalDefaults(t *testing.T) {
	global := ProtectionPolicyConfig{WebAttack: "strict", APISecurity: "smart", BotCC: "high", ThreatIntel: "low"}
	site := ProtectionPolicyConfig{BotCC: "off"}
	got := EffectiveProtectionPolicy(global, site)
	if got.WebAttack != "strict" || got.APISecurity != "smart" || got.BotCC != "off" || got.ThreatIntel != "low" {
		t.Fatalf("unexpected effective policy: %+v", got)
	}
}

func TestApplyDefaultsMigratesDeprecatedBehaviorCAPTCHATypes(t *testing.T) {
	defaults := Default()
	t.Run("single deprecated type falls back to default", func(t *testing.T) {
		cfg := Default()
		cfg.Protection.Bot.CAPTCHAType = "sequence_click"
		applyDefaults(&cfg)
		if cfg.Protection.Bot.CAPTCHAType != defaults.Protection.Bot.CAPTCHAType {
			t.Fatalf("captcha_type = %q, want default %q", cfg.Protection.Bot.CAPTCHAType, defaults.Protection.Bot.CAPTCHAType)
		}
	})
	t.Run("lists filter deprecated values and deduplicate", func(t *testing.T) {
		cfg := Default()
		cfg.Protection.Bot.CAPTCHATypes = []string{"pow", "sequence_click", "pow", "scramble_jigsaw", "shape_slider"}
		cfg.Protection.Bot.CAPTCHAEscalationTypes = []string{"scramble_jigsaw", "rotate", "rotate", "sequence_click"}
		applyDefaults(&cfg)
		if got, want := cfg.Protection.Bot.CAPTCHATypes, []string{"pow", "shape_slider"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("captcha_types = %#v, want %#v", got, want)
		}
		if got, want := cfg.Protection.Bot.CAPTCHAEscalationTypes, []string{"rotate"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("captcha_escalation_types = %#v, want %#v", got, want)
		}
	})
	t.Run("deprecated-only lists fall back to defaults", func(t *testing.T) {
		cfg := Default()
		cfg.Protection.Bot.CAPTCHATypes = []string{"sequence_click", "scramble_jigsaw", "sequence_click"}
		cfg.Protection.Bot.CAPTCHAEscalationTypes = []string{"scramble_jigsaw"}
		applyDefaults(&cfg)
		if !reflect.DeepEqual(cfg.Protection.Bot.CAPTCHATypes, defaults.Protection.Bot.CAPTCHATypes) {
			t.Fatalf("captcha_types = %#v, want defaults %#v", cfg.Protection.Bot.CAPTCHATypes, defaults.Protection.Bot.CAPTCHATypes)
		}
		if !reflect.DeepEqual(cfg.Protection.Bot.CAPTCHAEscalationTypes, defaults.Protection.Bot.CAPTCHAEscalationTypes) {
			t.Fatalf("captcha_escalation_types = %#v, want defaults %#v", cfg.Protection.Bot.CAPTCHAEscalationTypes, defaults.Protection.Bot.CAPTCHAEscalationTypes)
		}
	})
}
