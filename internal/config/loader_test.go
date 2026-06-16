package config

import (
	"os"
	"path/filepath"
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
