package config

import (
	"testing"
	"time"
)

func TestPHP2ShellDefaultsEnabled(t *testing.T) {
	cfg := Default()
	if len(cfg.Sites) == 0 {
		t.Fatal("default config has no site")
	}
	if !cfg.Sites[0].WAF.PHP2Shell.IsEnabled() {
		t.Fatal("PHP2Shell detector must default enabled")
	}
	if cfg.Sites[0].WAF.PHP2Shell.MaxParts != 256 ||
		cfg.Sites[0].WAF.PHP2Shell.MaxArrayDepth != 6 ||
		cfg.Sites[0].WAF.PHP2Shell.MaxEmptyFilenameParts != 32 {
		t.Fatalf("unexpected PHP2Shell defaults: %+v", cfg.Sites[0].WAF.PHP2Shell)
	}
}

func TestPHP2ShellExplicitDisable(t *testing.T) {
	cfg := Default()
	disabled := false
	cfg.Sites[0].WAF.PHP2Shell.Enabled = &disabled
	if cfg.Sites[0].WAF.PHP2Shell.IsEnabled() {
		t.Fatal("explicit disable was ignored")
	}
}

func TestIntelDefaultsFailClosed(t *testing.T) {
	cfg := Default()
	if !cfg.Intel.Enabled {
		t.Fatal("intel read-only pipeline should be available by default")
	}
	if cfg.Intel.AutoApply || !cfg.Intel.RequireHumanApproval {
		t.Fatalf("intel must not auto-apply: %+v", cfg.Intel)
	}
	if cfg.Intel.ShadowWindow <= 0 || cfg.Intel.MaxFetchBytes <= 0 {
		t.Fatalf("intel bounds not defaulted: %+v", cfg.Intel)
	}
}

func TestNotifierFeishuAndEmailValidation(t *testing.T) {
	cfg := Default()
	cfg.Monitor.Notifiers = []NotifierConfig{
		{ID: "feishu", Type: "feishu", Endpoint: "https://open.feishu.cn/open-apis/bot/v2/hook/x", Enabled: true},
		{ID: "mail", Type: "email", Endpoint: "smtp://smtp.example.com:587", To: "ops@example.com", Headers: map[string]string{"from": "waf@example.com"}, Enabled: true},
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid notifiers rejected: %v", err)
	}
	cfg.Monitor.Notifiers[1].Headers = nil
	if err := Validate(&cfg); err == nil {
		t.Fatal("email without sender must be rejected")
	}
}

func TestPasskeyConfigRequiresHTTPSOrigin(t *testing.T) {
	cfg := Default()
	cfg.Console.Login.Passkey = PasskeyConfig{
		Enabled: true, RPDisplayName: "CheeseWAF", RPID: "waf.example.com",
		RPOrigins: []string{"http://waf.example.com"},
	}
	if err := Validate(&cfg); err == nil {
		t.Fatal("plain HTTP passkey origin must be rejected")
	}
	cfg.Console.Login.Passkey.RPOrigins = []string{"https://waf.example.com"}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid passkey config rejected: %v", err)
	}
}

func TestIntelPollIntervalDefaultsAndBounds(t *testing.T) {
	cfg := Default()
	if cfg.Intel.PollInterval != 15*time.Minute {
		t.Fatalf("intel.poll_interval default = %s", cfg.Intel.PollInterval)
	}
	cfg.Intel.Enabled = true
	cfg.Intel.PollInterval = 5 * time.Second
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected short intel poll interval to be rejected")
	}
	cfg.Intel.PollInterval = 15 * time.Minute
	if err := Validate(&cfg); err != nil {
		t.Fatalf("default intel poll interval rejected: %v", err)
	}
}
