package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSampleConfigLoadsBotProtection(t *testing.T) {
	cfg, err := Load("../../configs/cheesewaf.yaml")
	if err != nil {
		t.Fatalf("load sample config: %v", err)
	}
	if cfg.Protection.Bot.AltchaMaxNumber != 75000 {
		t.Fatalf("unexpected altcha max number %d", cfg.Protection.Bot.AltchaMaxNumber)
	}
	if cfg.Protection.Bot.AltchaHeaderName != "X-CheeseWAF-Altcha" {
		t.Fatalf("unexpected altcha header %q", cfg.Protection.Bot.AltchaHeaderName)
	}
}

func TestSampleConfigDocumentsPrivateSSHDeploymentOptIn(t *testing.T) {
	data, err := os.ReadFile("../../configs/cheesewaf.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	if !strings.Contains(contents, "allow_private_targets: false") ||
		!strings.Contains(contents, "RFC1918") ||
		!strings.Contains(contents, "IPv6 ULA") {
		t.Fatalf("sample config must document the narrow private SSH target opt-in")
	}
}

// The checked-in sample is copied into release archives and used as the first
// bootstrap configuration. It must stay portable and must never contain a
// developer's runtime state or a reusable signing secret.
func TestSampleConfigIsPortableAndSecretFree(t *testing.T) {
	const samplePath = "../../configs/cheesewaf.yaml"
	data, err := os.ReadFile(samplePath)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(data)
	for _, marker := range []string{
		"/Users/",
		"/home/",
		"C:/Users/",
		"C:\\Users\\",
		"D:/Users/",
		"D:\\Users\\",
	} {
		if strings.Contains(contents, marker) {
			t.Fatalf("sample config contains a machine-specific path marker %q", marker)
		}
	}

	cfg, err := Load(samplePath)
	if err != nil {
		t.Fatalf("load sample config: %v", err)
	}

	for _, item := range []struct {
		name  string
		value string
	}{
		{"server.admin_tls.cert_file", cfg.Server.AdminTLS.CertFile},
		{"server.admin_tls.key_file", cfg.Server.AdminTLS.KeyFile},
		{"tls.cert_file", cfg.TLS.CertFile},
		{"tls.key_file", cfg.TLS.KeyFile},
		{"setup.data_dir", cfg.Setup.DataDir},
		{"setup.runtime_dir", cfg.Setup.RuntimeDir},
		{"captcha_assets.local.path", cfg.CAPTCHAAssets.Local.Path},
		{"protection.ip.geoip.database", cfg.Protection.IP.GeoIP.Database},
		{"storage.sqlite.path", cfg.Storage.SQLite.Path},
		{"logging.output.file.path", cfg.Logging.Output.File.Path},
		{"apisec.auth.jwks_cache_file", cfg.APISec.Auth.JWKSCacheFile},
		{"apisec.audit.path", cfg.APISec.Audit.Path},
	} {
		if filepath.IsAbs(item.value) || windowsAbsolutePath(item.value) {
			t.Fatalf("sample config path %s must be relative, got %q", item.name, item.value)
		}
	}
	for i, task := range cfg.Scheduler.Tasks {
		for _, item := range []struct {
			name  string
			value string
		}{
			{taskFieldName(i, "target"), task.Target},
			{taskFieldName(i, "recipient"), task.Recipient},
		} {
			if item.value != "" && !strings.HasPrefix(strings.ToLower(item.value), "http://") && !strings.HasPrefix(strings.ToLower(item.value), "https://") && (filepath.IsAbs(item.value) || windowsAbsolutePath(item.value)) {
				t.Fatalf("sample config path %s must be relative, got %q", item.name, item.value)
			}
		}
	}

	if secret := strings.TrimSpace(cfg.Protection.Bot.Secret); secret != "" && secret != BotSecretPlaceholder {
		t.Fatal("sample config must not contain a reusable bot secret")
	}
	for _, item := range []struct {
		name  string
		value string
	}{
		{"ai.api_key", cfg.AI.APIKey},
		{"ai.assistant.api_key", cfg.AI.Assistant.APIKey},
		{"ai.reasoning.api_key", cfg.AI.Reasoning.APIKey},
		{"apisec.auth.jwt_shared_secret", cfg.APISec.Auth.JWTSharedSecret},
		{"storage.clickhouse.password", cfg.Storage.ClickHouse.Password},
		{"storage.elasticsearch.password", cfg.Storage.Elasticsearch.Password},
		{"storage.elasticsearch.api_key", cfg.Storage.Elasticsearch.APIKey},
	} {
		if strings.TrimSpace(item.value) != "" {
			t.Fatalf("sample config field %s must be empty", item.name)
		}
	}
	for i, provider := range cfg.ACME.DNSProviders {
		for key, value := range provider.Env {
			if strings.TrimSpace(value) != "" {
				t.Fatalf("sample config acme.dns_providers[%d].env[%s] must be empty", i, key)
			}
		}
	}
	if len(cfg.APISec.ManagementAPI.Tokens) != 0 {
		t.Fatal("sample config must not contain management API tokens")
	}
}

func taskFieldName(index int, field string) string {
	return "scheduler.tasks[" + strconv.Itoa(index) + "]." + field
}

func windowsAbsolutePath(value string) bool {
	if runtime.GOOS == "windows" {
		return filepath.IsAbs(value)
	}
	return len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '/' || value[2] == '\\')
}
