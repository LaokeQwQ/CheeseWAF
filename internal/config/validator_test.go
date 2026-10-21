package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/protection/tamper"
)

func TestValidateThreatIntelIndicatorTypes(t *testing.T) {
	cases := []struct {
		name string
		item ThreatIntelConfig
		good bool
	}{
		{"domain", ThreatIntelConfig{Type: "domain", Value: "evil.example"}, true},
		{"url", ThreatIntelConfig{Type: "url", Value: "https://evil.example/path"}, true},
		{"sha256", ThreatIntelConfig{Type: "sha256", Value: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}, true},
		{"asn", ThreatIntelConfig{Type: "asn", Value: "AS64500"}, true},
		{"ja3", ThreatIntelConfig{Type: "ja3", Value: "0123456789abcdef0123456789abcdef"}, true},
		{"ja4", ThreatIntelConfig{Type: "ja4", Value: "t13d1516h2_8daaf6152771_0273b62f6f95"}, true},
		{"wide cidr", ThreatIntelConfig{Type: "ip", Value: "0.0.0.0/0"}, false},
		{"mapped wide cidr", ThreatIntelConfig{Type: "ip", Value: "::ffff:0.0.0.0/96"}, false},
		{"mapped short prefix", ThreatIntelConfig{Type: "ip", Value: "::ffff:1.2.3.4/95"}, false},
		{"mapped public cidr", ThreatIntelConfig{Type: "ip", Value: "::ffff:8.8.8.0/120"}, true},
		{"unspecified cidr", ThreatIntelConfig{Type: "ip", Value: "0.0.0.0/8"}, false},
		{"unspecified ip", ThreatIntelConfig{Type: "ip", Value: "0.0.0.0"}, false},
		{"unspecified ipv6", ThreatIntelConfig{Type: "ip", Value: "::"}, false},
		{"private cidr", ThreatIntelConfig{Type: "ip", Value: "10.0.0.0/8"}, false},
		{"private ip", ThreatIntelConfig{Type: "ip", Value: "10.0.0.1"}, false},
		{"unknown type", ThreatIntelConfig{Type: "opaque", Value: "evil.example"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateThreatIntelIndicator(tc.item)
			if (err == nil) != tc.good {
				t.Fatalf("validateThreatIntelIndicator(%+v) = %v, want valid=%v", tc.item, err, tc.good)
			}
		})
	}
}

func TestResolveManagedSchedulerPath(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	dataDir := filepath.Join(base, "data")
	logDir := filepath.Join(base, "logs")
	for _, root := range []string{dataDir, logDir} {
		if err := os.MkdirAll(root, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		target string
		want   string
	}{
		{"./reports", filepath.Join(dataDir, "reports")},
		{"./data/reports", filepath.Join(dataDir, "reports")},
		{"./logs/reports", filepath.Join(logDir, "reports")},
		{"./logs", logDir},
		{filepath.Join(dataDir, "reports"), filepath.Join(dataDir, "reports")},
	} {
		t.Run(tc.target, func(t *testing.T) {
			got, err := ResolveManagedSchedulerPath(tc.target, "", ".", dataDir, logDir)
			if err != nil || got != tc.want {
				t.Fatalf("ResolveManagedSchedulerPath(%q) = %q, %v; want %q", tc.target, got, err, tc.want)
			}
		})
	}
	outside := t.TempDir()
	for _, tc := range []struct {
		name string
		link string
		dest string
	}{
		{"outside link", "escape", outside},
		{"inside link", "alias", logDir},
		{"dangling link", "dangling", filepath.Join(outside, "missing")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := filepath.Join(dataDir, tc.link)
			if err := os.Symlink(tc.dest, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if _, err := ResolveManagedSchedulerPath(filepath.Join(link, "reports"), dataDir, logDir); err == nil {
				t.Fatal("scheduler path through a symlink must be rejected")
			}
		})
	}
	for _, target := range []string{"", "../reports", outside} {
		if _, err := ResolveManagedSchedulerPath(target, dataDir, logDir); err == nil {
			t.Fatalf("unsafe scheduler path %q was accepted", target)
		}
	}
}

func TestResolveManagedSchedulerPathBeforeFreshInstall(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fresh", "install", "data")
	for _, target := range []string{root, "./reports", "./data/reports"} {
		got, err := ResolveManagedSchedulerPath(target, root)
		if err != nil {
			t.Fatalf("fresh install directory %q must validate: %v", target, err)
		}
		want := filepath.Join(root, "reports")
		if target == root {
			want = root
		}
		if got != want {
			t.Fatalf("resolved %q as %q, want %q", target, got, want)
		}
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("validation must not create the installation directory: %v", err)
	}
}

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

func TestValidateCAPTCHAProviderPublicURLs(t *testing.T) {
	tests := []struct {
		name        string
		field       string
		value       string
		trailing    bool
		wantErrText string
	}{
		{name: "site key endpoint", field: "api_endpoint", value: "https://cap.example/site-key/", trailing: true},
		{name: "loopback development endpoint", field: "api_endpoint", value: "http://127.0.0.1:3000/site-key/", trailing: true},
		{name: "root is not a site key", field: "api_endpoint", value: "https://cap.example/", trailing: true, wantErrText: "site key"},
		{name: "missing trailing slash", field: "api_endpoint", value: "https://cap.example/site-key", trailing: true, wantErrText: "site key"},
		{name: "public http is denied", field: "widget_url", value: "http://cap.example/widget.js", wantErrText: "HTTPS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCAPublicURL("captcha_providers.cap."+tt.field, tt.value, tt.trailing)
			if tt.wantErrText == "" && err != nil {
				t.Fatalf("validateCAPublicURL() error = %v", err)
			}
			if tt.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrText)) {
				t.Fatalf("validateCAPublicURL() error = %v, want %q", err, tt.wantErrText)
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

func TestValidatorBodyInspectionLimitMatchesEngineAdmission(t *testing.T) {
	t.Run("64 MiB boundary accepted", func(t *testing.T) {
		cfg := Default()
		cfg.Sites[0].WAF.Performance.MaxBodyBytes = 64 << 20
		if err := Validate(&cfg); err != nil {
			t.Fatalf("configured engine admission boundary rejected: %v", err)
		}
	})
	t.Run("above boundary rejected", func(t *testing.T) {
		cfg := Default()
		cfg.Sites[0].WAF.Performance.MaxBodyBytes = (64 << 20) + 1
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "64MiB inspection ceiling") {
			t.Fatalf("error=%v, want explicit 64 MiB inspection ceiling", err)
		}
	})
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
	t.Run("explicit non-expiring token cannot carry expiry", func(t *testing.T) {
		cfg := Default()
		cfg.APISec.ManagementAPI.Enabled = true
		cfg.APISec.ManagementAPI.Tokens = []ManagementAPITokenConfig{{
			ID: "forever", Name: "forever", Prefix: "cwapi_forever", Hash: "sha256:" + strings.Repeat("0", 64),
			Scopes: []string{"read:system"}, Enabled: true, NeverExpire: true,
			CreatedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC),
		}}
		if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "never_expire") {
			t.Fatalf("expected explicit lifetime consistency error, got %v", err)
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

func TestValidatorNormalizesLegacyWAFLogMode(t *testing.T) {
	cfg := Default()
	cfg.Sites[0].WAF.Mode = "log"
	if err := Validate(&cfg); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := cfg.Sites[0].WAF.Mode; got != "monitor" {
		t.Fatalf("legacy waf mode was not persisted as monitor: %q", got)
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

func TestValidateRejectsMalformedUpstreamAndAcceptsIPv6AndWebSocketSchemes(t *testing.T) {
	base := Default()
	base.Sites = []SiteConfig{{
		Name:      "edge",
		Enabled:   true,
		Domains:   []string{"edge.example.test"},
		Upstreams: []UpstreamConfig{{Address: "http://[2001:db8::1]:8443"}},
	}}
	if err := Validate(&base); err != nil {
		t.Fatalf("IPv6 upstream rejected: %v", err)
	}

	for _, address := range []string{"http://[2001:db8::1", "ftp://backend:21", "http://backend:70000", "http://user:pass@backend"} {
		cfg := base
		cfg.Sites = append([]SiteConfig(nil), base.Sites...)
		cfg.Sites[0].Upstreams = []UpstreamConfig{{Address: address}}
		if err := Validate(&cfg); err == nil {
			t.Fatalf("Validate accepted malformed upstream %q", address)
		}
	}

	for _, address := range []string{"ws://backend:8080", "wss://backend:8443", "backend:8080"} {
		cfg := base
		cfg.Sites = append([]SiteConfig(nil), base.Sites...)
		cfg.Sites[0].Upstreams = []UpstreamConfig{{Address: address}}
		if err := Validate(&cfg); err != nil {
			t.Fatalf("Validate rejected supported upstream %q: %v", address, err)
		}
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
