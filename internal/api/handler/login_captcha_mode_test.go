package handler

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestLoginCaptchaEffectiveModeAllowsServerSupportedPowFallback(t *testing.T) {
	cfg := config.Default().Console.Login.CAPTCHA
	cfg.Mode = "slider"
	if got := loginCaptchaEffectiveMode(cfg, "pow"); got != "pow" {
		t.Fatalf("configured slider mode must allow the PoW fallback, got %q", got)
	}
}

func TestLoginCaptchaEffectiveModeRejectsSliderDowngrade(t *testing.T) {
	cfg := config.Default().Console.Login.CAPTCHA
	cfg.Mode = "pow"
	if got := loginCaptchaEffectiveMode(cfg, "slider"); got != "pow" {
		t.Fatalf("configured PoW must not be downgraded by the client, got %q", got)
	}
}

func TestLoginCaptchaEffectiveModeIgnoresUnknownClientMode(t *testing.T) {
	cfg := config.Default().Console.Login.CAPTCHA
	cfg.Mode = "slider"
	if got := loginCaptchaEffectiveMode(cfg, "custom"); got != "slider" {
		t.Fatalf("unknown client mode changed the configured flow: %q", got)
	}
}
