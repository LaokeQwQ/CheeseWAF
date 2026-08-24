package config

import (
	"os"
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
