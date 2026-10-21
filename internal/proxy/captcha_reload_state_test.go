package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestCAPTCHAProviderReloadKeepsPendingChallengeAndRateQuota(t *testing.T) {
	for _, update := range []string{"same providers", "unrelated protection", "unused provider settings"} {
		t.Run(update, func(t *testing.T) {
			cfg := reviewProxyConfig("http://127.0.0.1:1")
			cfg.Protection.Bot.Enabled = true
			cfg.Protection.Bot.CAPTCHA = true
			cfg.Protection.Bot.CAPTCHAProvider = "builtin"
			cfg.Protection.Bot.CAPTCHAType = "pow"
			cfg.Protection.Bot.CAPTCHATypes = []string{"pow"}
			cfg.Protection.Bot.CAPTCHAEscalationTypes = nil
			cfg.Protection.Bot.CookieName = bug067068CookieName
			cfg.Protection.Bot.ChallengeDifficulty = 1
			cfg.Protection.Bot.PoWMaxDifficulty = 1
			cfg.Protection.RateLimit.Enabled = true
			cfg.Protection.RateLimit.Default = config.RateLimitProfile{Requests: 1, Burst: 0, Window: time.Minute}
			server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			const client = "198.51.100.8"
			if !server.limiter.Allow(client) || server.limiter.Allow(client) {
				t.Fatal("fixture did not consume its rate quota")
			}
			issue := httptest.NewRequest(http.MethodGet, "https://localhost/private", nil)
			issue.Header.Set("User-Agent", bug067068UserAgent)
			page := httptest.NewRecorder()
			server.bot.ServeChallengeForSite(page, issue, client, "site-a")
			challenge := requireBUG067068PoWChallenge(t, page)
			answer := solveBUG067068PoW(t, challenge)
			oldBot := server.bot
			switch update {
			case "same providers":
				err = server.UpdateCAPTCHAProviders(cfg.CAPTCHAProviders)
			case "unrelated protection":
				protection := cfg.Protection
				protection.Policy.WebAttack = config.ProtectionLevelStrict
				err = server.UpdateProtection(protection)
			case "unused provider settings":
				providers := cfg.CAPTCHAProviders
				providers.Cap.Timeout += time.Second
				err = server.UpdateCAPTCHAProviders(providers)
			}
			if err != nil {
				t.Fatal(err)
			}
			if server.limiter.Allow(client) {
				t.Error("unrelated update reset an exhausted rate quota")
			}
			if server.bot != oldBot {
				t.Error("unrelated update discarded the active bot state")
			}
			// Redeem the proof issued before reload through the active policy.
			form := url.Values{"cw_pow_token": {challenge.token}, "cw_pow_answer": {answer}}
			verify := httptest.NewRequest(http.MethodPost, "https://localhost/private", strings.NewReader(form.Encode()))
			verify.Header.Set("User-Agent", bug067068UserAgent)
			verify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			result := httptest.NewRecorder()
			server.bot.ServeChallengeForSite(result, verify, client, "site-a")
			if result.Code != http.StatusSeeOther {
				t.Fatalf("pending challenge was lost across reload: status=%d", result.Code)
			}
		})
	}
}

func TestCapRuntimeReloadPreservesPendingProof(t *testing.T) {
	for _, update := range []string{"same providers", "unrelated protection", "failed provider"} {
		t.Run(update, func(t *testing.T) {
			var calls atomic.Int32
			capServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"success":true}`))
			}))
			t.Cleanup(capServer.Close)
			secret := filepath.Join(t.TempDir(), "cap-secret")
			if err := os.WriteFile(secret, []byte("local-cap-secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := reviewProxyConfig("http://127.0.0.1:1")
			cfg.Protection.Bot.Enabled = true
			cfg.Protection.Bot.CAPTCHA = true
			cfg.Protection.Bot.CAPTCHAProvider = "cap"
			cfg.Protection.Bot.CAPTCHAType = "pow"
			cfg.Protection.Bot.CAPTCHATypes = []string{"pow"}
			cfg.Protection.Bot.CAPTCHAEscalationTypes = nil
			cfg.CAPTCHAProviders.Cap = config.CapStandaloneConfig{
				APIEndpoint: capServer.URL + "/site-key/", WidgetURL: capServer.URL + "/widget.js",
				WASMURL: capServer.URL + "/cap.wasm", HashWXURL: capServer.URL + "/hash.wasm",
				SecretFile: secret, Timeout: time.Second,
			}
			server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			issue := httptest.NewRequest(http.MethodGet, "https://localhost/private", nil)
			issue.Header.Set("User-Agent", bug067068UserAgent)
			page := httptest.NewRecorder()
			server.bot.ServeChallengeForSite(page, issue, "198.51.100.8", "site-a")
			form := url.Values{"cw_cap_token": {"local-cap-token"}}
			for _, match := range regexp.MustCompile(`name="(cw_cap_challenge_id|cw_cap_context|cw_cap_method)" value="([^"]*)"`).FindAllStringSubmatch(page.Body.String(), -1) {
				form.Set(match[1], match[2])
			}
			if page.Code != http.StatusForbidden || form.Get("cw_cap_challenge_id") == "" || form.Get("cw_cap_context") == "" {
				t.Fatal("fixture did not issue a pending Cap challenge")
			}
			oldBot := server.bot
			switch update {
			case "same providers":
				err = server.UpdateCAPTCHAProviders(cfg.CAPTCHAProviders)
			case "unrelated protection":
				protection := cfg.Protection
				protection.Policy.WebAttack = config.ProtectionLevelStrict
				err = server.UpdateProtection(protection)
			case "failed provider":
				providers := cfg.CAPTCHAProviders
				providers.Cap.SecretFile = filepath.Join(t.TempDir(), "missing")
				if err = server.UpdateCAPTCHAProviders(providers); err == nil {
					t.Fatal("invalid provider update succeeded")
				}
				err = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			if server.bot != oldBot || server.captchaProviders != cfg.CAPTCHAProviders {
				t.Fatal("unchanged or rejected provider update replaced active state")
			}
			verify := httptest.NewRequest(http.MethodPost, "https://localhost/private", strings.NewReader(form.Encode()))
			verify.Header.Set("User-Agent", bug067068UserAgent)
			verify.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			result := httptest.NewRecorder()
			server.bot.ServeChallengeForSite(result, verify, "198.51.100.8", "site-a")
			if result.Code != http.StatusSeeOther || calls.Load() != 1 {
				t.Fatalf("pending Cap proof lost: status=%d verification calls=%d", result.Code, calls.Load())
			}
		})
	}
}
