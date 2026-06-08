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
