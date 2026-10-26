package handler

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxy"
)

func TestCapRuntimeJointProviderTransitionsAndRollback(t *testing.T) {
	for _, method := range []string{"file reload", "system update"} {
		t.Run(method, func(t *testing.T) {
			cfg := config.Default()
			cfg.Protection.Bot.Enabled = true
			cfg.Protection.Bot.CAPTCHA = true
			cfg.Protection.Bot.CAPTCHAProvider = "cap"
			secret := filepath.Join(t.TempDir(), "cap-secret")
			if err := os.WriteFile(secret, []byte("local-cap-secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.CAPTCHAProviders.Cap = config.CapStandaloneConfig{
				APIEndpoint: "http://127.0.0.1:1/site-key/", WidgetURL: "http://127.0.0.1:1/widget.js",
				WASMURL: "http://127.0.0.1:1/cap.wasm", HashWXURL: "http://127.0.0.1:1/hash.wasm",
				SecretFile: secret, Timeout: time.Second,
			}
			server, err := proxy.NewServer(&cfg, engine.NewPipeline(), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			var rejectAPISec bool
			h := New(Options{
				Config: &cfg, OnProtectionChanged: server.UpdateProtection,
				OnCAPTCHAProvidersChanged: server.UpdateCAPTCHAProviders,
				OnAPISecChanged: func(config.APISecConfig) error {
					if rejectAPISec {
						return errors.New("later runtime failure")
					}
					return nil
				},
			})
			apply := func(candidate *config.Config) error {
				if method == "file reload" {
					return h.applyLiveRuntime(candidate)
				}
				return h.applySystemRuntime(systemPayload{
					Protection: &candidate.Protection, CAPTCHAProviders: &candidate.CAPTCHAProviders,
					APISec: &candidate.APISec,
				}, candidate)
			}
			disabled, err := config.Clone(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			disabled.Protection.Bot.CAPTCHAProvider = "builtin"
			disabled.CAPTCHAProviders = config.CAPTCHAProvidersConfig{}
			if err := config.Validate(disabled); err != nil {
				t.Fatalf("fixture should be a valid disabled-Cap configuration: %v", err)
			}
			if err := apply(disabled); err != nil {
				t.Fatalf("joint Cap disable/provider cleanup failed: %v", err)
			}
			if err := apply(&cfg); err != nil {
				t.Fatalf("joint Cap enable failed: %v", err)
			}
			// A later callback failure must permit the existing transaction to
			// apply its previous snapshot in the reverse transition as well.
			rejectAPISec = true
			if err := apply(disabled); err == nil {
				t.Fatal("later runtime failure unexpectedly succeeded")
			}
			rejectAPISec = false
			if err := apply(&cfg); err != nil {
				t.Fatalf("rollback to Cap configuration failed: %v", err)
			}
		})
	}
}
