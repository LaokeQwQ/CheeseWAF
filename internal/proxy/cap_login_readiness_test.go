package proxy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestServerRequiresConsoleCapSecretBeforeStartup(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "directory", "oversized", "valid", "builtin", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			cfg := reviewProxyConfig("http://127.0.0.1:1")
			cfg.Protection.Bot.CAPTCHAProvider = "builtin"
			cfg.Console.Login.CAPTCHA.Enabled = true
			cfg.Console.Login.CAPTCHA.Provider = "cap"
			secret := filepath.Join(t.TempDir(), "cap-secret")
			if kind == "directory" {
				if err := os.Mkdir(secret, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if kind != "missing" && kind != "builtin" && kind != "disabled" {
				contents := []byte("local-cap-secret")
				if kind == "empty" {
					contents = []byte(" \n\t")
				} else if kind == "oversized" {
					contents = bytes.Repeat([]byte{'x'}, 4097)
				}
				if err := os.WriteFile(secret, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "builtin" {
				cfg.Console.Login.CAPTCHA.Provider = "builtin"
			} else if kind == "disabled" {
				cfg.Console.Login.CAPTCHA.Enabled = false
			}
			cfg.CAPTCHAProviders.Cap = config.CapStandaloneConfig{
				APIEndpoint: "https://cap.example.test/site-key/", WidgetURL: "https://cap.example.test/widget.js",
				WASMURL: "https://cap.example.test/cap.wasm", HashWXURL: "https://cap.example.test/hash.wasm",
				SecretFile: secret, Timeout: time.Second,
			}
			server, err := NewServer(&cfg, engine.NewPipeline(), noopSink{})
			wantValid := kind == "valid" || kind == "builtin" || kind == "disabled"
			if server != nil {
				_ = server.Close()
			}
			if wantValid && err != nil {
				t.Fatalf("valid startup failed: %v", err)
			} else if !wantValid && err == nil {
				t.Fatal("server started with an unusable Cap login secret")
			}
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Fatal("startup error leaked the secret path")
			}
		})
	}
}
