package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func capLoginReadinessConfig(secret string) config.Config {
	cfg := config.Default()
	cfg.Protection.Bot.CAPTCHAProvider = "builtin"
	cfg.CAPTCHAProviders.Cap = config.CapStandaloneConfig{
		APIEndpoint: "https://cap.example.test/site-key/", WidgetURL: "https://cap.example.test/widget.js",
		WASMURL: "https://cap.example.test/cap.wasm", HashWXURL: "https://cap.example.test/hash.wasm",
		SecretFile: secret, Timeout: time.Second,
	}
	return cfg
}

func capLoginReadinessFile(t *testing.T, kind string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cap-secret")
	switch kind {
	case "missing":
		return path
	case "directory":
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	contents := []byte("local-cap-secret")
	if kind == "empty" {
		contents = []byte(" \n\t")
	} else if kind == "oversized" {
		contents = bytes.Repeat([]byte{'x'}, 4097)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCapLoginReadinessRejectsInvalidSecretBeforeSystemMutation(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "directory", "oversized"} {
		for _, joint := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "/console-only", true: "/console-and-provider"}[joint], func(t *testing.T) {
				secret := capLoginReadinessFile(t, kind)
				cfg := capLoginReadinessConfig(secret)
				path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
				if err := config.Save(path, &cfg); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				h := New(Options{
					Config: &cfg, ConfigPath: path,
					OnProtectionChanged:       func(config.ProtectionConfig) error { calls++; return nil },
					OnCAPTCHAProvidersChanged: func(config.CAPTCHAProvidersConfig) error { calls++; return nil },
				})
				previous, err := config.Clone(h.currentConfig())
				if err != nil {
					t.Fatal(err)
				}
				console := cfg.Console
				console.Login.CAPTCHA.Provider = "cap"
				payload := map[string]any{"console": console}
				if joint {
					providers := cfg.CAPTCHAProviders
					providers.Cap.APIEndpoint = "https://new-cap.example.test/site-key/"
					payload["captcha_providers"] = providers
				}
				body, _ := json.Marshal(payload)
				rec := httptest.NewRecorder()
				h.UpdateSystem(rec, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(body)))
				if rec.Code < 400 {
					t.Fatalf("unreadable Cap login was enabled: status=%d", rec.Code)
				}
				if strings.Contains(rec.Body.String(), secret) {
					t.Fatal("error leaked the configured secret path")
				}
				if calls != 0 || !reflect.DeepEqual(previous, h.currentConfig()) || h.configWriteFrozen {
					t.Fatalf("invalid provider changed active state: callbacks=%d frozen=%v", calls, h.configWriteFrozen)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("invalid provider changed the persisted file")
				}
			})
		}
	}
}

func TestCapLoginReadinessReloadRejectsBeforeRuntimeCallbacks(t *testing.T) {
	valid := capLoginReadinessFile(t, "valid")
	cfg := capLoginReadinessConfig(valid)
	cfg.Console.Login.CAPTCHA.Provider = "cap"
	callbacks := 0
	h := New(Options{Config: &cfg,
		OnSitesChanged:            func([]config.SiteConfig) error { callbacks++; return nil },
		OnCAPTCHAProvidersChanged: func(config.CAPTCHAProvidersConfig) error { callbacks++; return nil },
	})
	previous, _ := config.Clone(h.currentConfig())
	next, _ := config.Clone(previous)
	next.CAPTCHAProviders.Cap.SecretFile = capLoginReadinessFile(t, "missing")
	if err := h.ReloadLiveConfig(next); err == nil {
		t.Fatal("file reload published an unreadable login provider")
	}
	if callbacks != 0 || !reflect.DeepEqual(previous, h.currentConfig()) || h.configWriteFrozen {
		t.Fatalf("failed readiness check changed runtime: callbacks=%d frozen=%v", callbacks, h.configWriteFrozen)
	}
}

func TestCapLoginReadinessAllowsValidAndDisabledRecovery(t *testing.T) {
	for _, mode := range []string{"valid-cap", "builtin-recovery", "disabled-recovery"} {
		t.Run(mode, func(t *testing.T) {
			secret := capLoginReadinessFile(t, "valid")
			cfg := capLoginReadinessConfig(secret)
			if mode != "valid-cap" {
				cfg.Console.Login.CAPTCHA.Provider = "cap"
				if err := os.Remove(secret); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
			if err := config.Save(path, &cfg); err != nil {
				t.Fatal(err)
			}
			h := New(Options{Config: &cfg, ConfigPath: path})
			console := cfg.Console
			console.Login.CAPTCHA.Provider = "cap"
			console.Login.CAPTCHA.Enabled = mode != "disabled-recovery"
			if mode == "builtin-recovery" {
				console.Login.CAPTCHA.Provider = "builtin"
			}
			body, _ := json.Marshal(map[string]any{"console": console, "captcha_providers": cfg.CAPTCHAProviders})
			rec := httptest.NewRecorder()
			h.UpdateSystem(rec, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(body)))
			if rec.Code != http.StatusOK || h.currentConfig().Console.Login.CAPTCHA.Enabled != console.Login.CAPTCHA.Enabled ||
				h.currentConfig().Console.Login.CAPTCHA.Provider != console.Login.CAPTCHA.Provider {
				t.Fatalf("valid or disabled login update failed: status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCapLoginReadinessDoesNotBlockUnrelatedConfigWrite(t *testing.T) {
	cfg := capLoginReadinessConfig(capLoginReadinessFile(t, "missing"))
	cfg.Console.Login.CAPTCHA.Provider = "cap"
	path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(path, &cfg); err != nil {
		t.Fatal(err)
	}
	h := New(Options{Config: &cfg, ConfigPath: path})
	console := cfg.Console
	console.Login.Copyright = "updated branding"
	body, _ := json.Marshal(map[string]any{"console": console})
	rec := httptest.NewRecorder()
	h.UpdateSystem(rec, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(body)))
	if rec.Code != http.StatusOK || h.currentConfig().Console.Login.Copyright != "updated branding" {
		t.Fatalf("unrelated write was blocked by existing provider state: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCapLoginReadinessPreservesTransactionRollback(t *testing.T) {
	cfg := capLoginReadinessConfig(capLoginReadinessFile(t, "valid"))
	path := filepath.Join(t.TempDir(), "cheesewaf.yaml")
	if err := config.Save(path, &cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	var active config.CAPTCHAProvidersConfig
	h := New(Options{Config: &cfg, ConfigPath: path,
		OnCAPTCHAProvidersChanged: func(providers config.CAPTCHAProvidersConfig) error { active = providers; return nil },
		OnAPISecChanged: func(config.APISecConfig) error {
			if active.Cap.APIEndpoint == "https://new-cap.example.test/site-key/" {
				return errors.New("later runtime failure")
			}
			return nil
		},
	})
	previous, _ := config.Clone(h.currentConfig())
	console := cfg.Console
	console.Login.CAPTCHA.Provider = "cap"
	providers := cfg.CAPTCHAProviders
	providers.Cap.APIEndpoint = "https://new-cap.example.test/site-key/"
	body, _ := json.Marshal(map[string]any{"console": console, "captcha_providers": providers, "apisec": cfg.APISec})
	rec := httptest.NewRecorder()
	h.UpdateSystem(rec, httptest.NewRequest(http.MethodPut, "/api/system", bytes.NewReader(body)))
	if rec.Code < 400 || !reflect.DeepEqual(previous, h.currentConfig()) || active != cfg.CAPTCHAProviders || h.configWriteFrozen {
		t.Fatalf("failed transaction was not restored: status=%d frozen=%v", rec.Code, h.configWriteFrozen)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed transaction changed persisted config")
	}
}
