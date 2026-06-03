package config

import "testing"

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
