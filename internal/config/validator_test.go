package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/protection/tamper"
)

func TestValidatorUpstreamWeightLimits(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
		errText string
	}{
		{
			name: "single upstream with excessive weight triggers error",
			mutate: func(cfg *Config) {
				cfg.Sites[0].Upstreams[0].Weight = 2000
			},
			wantErr: true,
			errText: "weight 2000 exceeds maximum 1000",
		},
		{
			name: "total weight exceeding 10000 triggers error",
			mutate: func(cfg *Config) {
				cfg.Sites[0].Upstreams = []UpstreamConfig{
					{Address: "localhost:8080", Weight: 920},
					{Address: "localhost:8081", Weight: 920},
					{Address: "localhost:8082", Weight: 920},
					{Address: "localhost:8083", Weight: 920},
					{Address: "localhost:8084", Weight: 920},
					{Address: "localhost:8085", Weight: 920},
					{Address: "localhost:8086", Weight: 920},
					{Address: "localhost:8087", Weight: 920},
					{Address: "localhost:8088", Weight: 920},
					{Address: "localhost:8089", Weight: 920},
					{Address: "localhost:8090", Weight: 920},
				}
			},
			wantErr: true,
			errText: "total upstream weight",
		},
		{
			name: "negative weight triggers error",
			mutate: func(cfg *Config) {
				cfg.Sites[0].Upstreams[0].Weight = -1
			},
			wantErr: true,
			errText: "has negative weight -1",
		},
		{
			name: "weight at boundary 1000 is valid",
			mutate: func(cfg *Config) {
				cfg.Sites[0].Upstreams[0].Weight = 1000
			},
			wantErr: false,
		},
		{
			name: "total weight at boundary 10000 is valid",
			mutate: func(cfg *Config) {
				cfg.Sites[0].Upstreams = []UpstreamConfig{
					{Address: "localhost:8080", Weight: 500},
					{Address: "localhost:8081", Weight: 500},
					{Address: "localhost:8082", Weight: 500},
					{Address: "localhost:8083", Weight: 500},
					{Address: "localhost:8084", Weight: 500},
					{Address: "localhost:8085", Weight: 500},
					{Address: "localhost:8086", Weight: 500},
					{Address: "localhost:8087", Weight: 500},
					{Address: "localhost:8088", Weight: 500},
					{Address: "localhost:8089", Weight: 500},
					{Address: "localhost:8090", Weight: 500},
					{Address: "localhost:8091", Weight: 500},
					{Address: "localhost:8092", Weight: 500},
					{Address: "localhost:8093", Weight: 500},
					{Address: "localhost:8094", Weight: 500},
					{Address: "localhost:8095", Weight: 500},
					{Address: "localhost:8096", Weight: 500},
					{Address: "localhost:8097", Weight: 500},
					{Address: "localhost:8098", Weight: 500},
					{Address: "localhost:8099", Weight: 500},
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			err := Validate(&cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errText)
				}
			}
		})
	}
}

func TestValidatorDecodeDepthBounds(t *testing.T) {
	for _, depth := range []int{0, 1, DefaultDecodeDepth, MaxDecodeDepth} {
		cfg := Default()
		cfg.Sites[0].WAF.SemanticPolicy.DecodeDepth = depth
		if err := Validate(&cfg); err != nil {
			t.Fatalf("depth %d rejected: %v", depth, err)
		}
	}
	for _, depth := range []int{-1, MaxDecodeDepth + 1} {
		cfg := Default()
		cfg.Sites[0].WAF.SemanticPolicy.DecodeDepth = depth
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "decode_depth") {
			t.Fatalf("depth %d error=%v, want decode_depth validation", depth, err)
		}
	}
}

func TestValidatorRejectsAmbiguousACLAndIPEntries(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "whitespace-only ACL selector",
			mutate: func(cfg *Config) {
				cfg.Protection.ACL.Rules = []ACLRuleConfig{{ID: "empty", Method: " ", PathPrefix: "\t", Enabled: true}}
			},
			wantErr: "must define a method",
		},
		{
			name: "header value without header",
			mutate: func(cfg *Config) {
				cfg.Protection.ACL.Rules = []ACLRuleConfig{{ID: "ambiguous", Method: "GET", HeaderValue: "secret", Enabled: true}}
			},
			wantErr: "header_value without header",
		},
		{
			name: "empty blacklist entry",
			mutate: func(cfg *Config) {
				cfg.Protection.IP.Blacklist = []string{"198.51.100.7", " "}
			},
			wantErr: "invalid blacklist entry",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidatorAcceptsAuthenticatedTamperSnapshot(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	snapshot, err := tamper.Capture(key, "/assets/app.js", []byte("clean"), time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Sites[0].WAF.Response.TamperKey = string(key)
	cfg.Sites[0].WAF.Response.TamperSnapshots = []TamperSnapshotConfig{{
		URL: snapshot.URL, MAC: snapshot.MAC, Size: snapshot.Size, CapturedAt: snapshot.CapturedAt,
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() rejected authenticated snapshot: %v", err)
	}

	cfg.Sites[0].WAF.Response.TamperKey = "short"
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "tamper MAC key") {
		t.Fatalf("Validate() weak-key error = %v", err)
	}
}

func TestValidatorBoundsManagementAPITokensAndRequiresUniquePrefixes(t *testing.T) {
	validToken := func(id int, prefix string) ManagementAPITokenConfig {
		return ManagementAPITokenConfig{
			ID: idString(id), Name: idString(id), Prefix: prefix,
			Hash: "sha256:" + strings.Repeat("0", 64), Scopes: []string{"read:system"}, Enabled: true,
		}
	}
	t.Run("total capacity", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = make([]ManagementAPITokenConfig, MaxManagementAPITokens+1)
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "exceed maximum") {
			t.Fatalf("expected token capacity error, got %v", err)
		}
	})
	t.Run("duplicate lookup prefix", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []ManagementAPITokenConfig{
			validToken(1, "cwapi_shared"), validToken(2, "cwapi_shared"),
		}
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "prefix") {
			t.Fatalf("expected duplicate prefix error, got %v", err)
		}
	})
}

func TestValidatorTrustedProxyProviderBindings(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*SiteAccessControlConfig)
		wantErr string
	}{
		{
			name: "valid explicit provider",
			mutate: func(access *SiteAccessControlConfig) {
				access.TrustedCIDRs = []string{"10.0.0.0/8"}
				access.TrustedProxyProviders = map[string][]string{
					"cloudflare": {"198.51.100.0/24"},
					"fastly":     {"192.0.2.10"},
				}
			},
		},
		{
			name: "unknown provider",
			mutate: func(access *SiteAccessControlConfig) {
				access.TrustedProxyProviders = map[string][]string{"typo-cdn": {"198.51.100.0/24"}}
			},
			wantErr: "unsupported trusted proxy provider",
		},
		{
			name: "provider requires CIDR",
			mutate: func(access *SiteAccessControlConfig) {
				access.TrustedProxyProviders = map[string][]string{"cloudflare": {}}
			},
			wantErr: "must define at least one CIDR",
		},
		{
			name: "provider rejects invalid CIDR",
			mutate: func(access *SiteAccessControlConfig) {
				access.TrustedProxyProviders = map[string][]string{"cloudflare": {"not-an-ip"}}
			},
			wantErr: "has invalid CIDR",
		},
		{
			name: "canonical provider cannot be duplicated by case",
			mutate: func(access *SiteAccessControlConfig) {
				access.TrustedProxyProviders = map[string][]string{
					"cloudflare": {"198.51.100.0/25"},
					"Cloudflare": {"198.51.100.128/25"},
				}
			},
			wantErr: "more than once",
		},
		{
			name: "total CIDRs are bounded",
			mutate: func(access *SiteAccessControlConfig) {
				access.TrustedCIDRs = make([]string, maxTrustedProxyCIDRs+1)
				for i := range access.TrustedCIDRs {
					access.TrustedCIDRs[i] = "127.0.0.1"
				}
			},
			wantErr: "maximum",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg.Sites[0].WAF.AccessControl)
			err := Validate(&cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid config: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateAdminTLSRequiredWhenAdminPublic(t *testing.T) {
	cfg := Default()
	cfg.Server.AdminPublic = true
	cfg.Server.AdminTLS.Enabled = false
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "admin_tls.enabled") {
		t.Fatalf("expected admin_tls.enabled error when admin_public=true, got %v", err)
	}
}

func TestValidateAdminTLSRequiredWhenNonLoopbackListen(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "wildcard", addr: "0.0.0.0:9443"},
		{name: "private", addr: "10.0.0.5:9443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.Server.AdminListen = tt.addr
			cfg.Server.AdminPublic = true
			cfg.Server.AdminTLS.Enabled = false
			if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "admin_tls.enabled") {
				t.Fatalf("expected admin_tls.enabled error for %s, got %v", tt.addr, err)
			}
		})
	}
}

func TestValidateAdminTLSAllowedOnLoopback(t *testing.T) {
	cfg := Default()
	cfg.Server.AdminListen = "127.0.0.1:9443"
	cfg.Server.AdminPublic = false
	cfg.Server.AdminTLS.Enabled = false
	if err := Validate(&cfg); err != nil {
		t.Fatalf("loopback admin without TLS should be valid: %v", err)
	}
}

func idString(id int) string { return fmt.Sprintf("token-%d", id) }

func TestValidateBoundsSiteHeaderAndRewriteComplexity(t *testing.T) {
	t.Run("header ceiling", func(t *testing.T) {
		cfg := Default()
		cfg.Sites[0].WAF.Performance.MaxHeaderBytes = 2 << 20
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "max_header_bytes") {
			t.Fatalf("expected max_header_bytes ceiling error, got %v", err)
		}
	})
	t.Run("rewrite count", func(t *testing.T) {
		cfg := Default()
		cfg.Sites[0].WAF.Rewrite = make([]RewriteRuleConfig, 129)
		for i := range cfg.Sites[0].WAF.Rewrite {
			cfg.Sites[0].WAF.Rewrite[i] = RewriteRuleConfig{ID: fmt.Sprint(i), Pattern: "^/old$", Replacement: "/new", Enabled: true}
		}
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "rewrite") {
			t.Fatalf("expected rewrite count error, got %v", err)
		}
	})
	t.Run("rewrite pattern length", func(t *testing.T) {
		cfg := Default()
		cfg.Sites[0].WAF.Rewrite = []RewriteRuleConfig{{ID: "long", Pattern: strings.Repeat("a", 5000), Replacement: "/new", Enabled: true}}
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "pattern") {
			t.Fatalf("expected rewrite pattern bound error, got %v", err)
		}
	})
}
