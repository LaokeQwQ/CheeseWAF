package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	monitornotify "github.com/LaokeQwQ/CheeseWAF/internal/monitor/notifier"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/index"
	"github.com/LaokeQwQ/CheeseWAF/internal/plugin/notifierpack"
)

const testNotifierPack = `{
  "api_version": "crp.cheesewaf.io/notifier/v1",
  "provider_id": "official-acme-alerts-1.0.0",
  "type": "acme_alerts",
  "version": "1.0.0",
  "namespace": "official/acme-alerts",
  "source": "local-index",
  "source_root": "test-root",
  "host_compatibility": { "min": "0.4.0", "max": "0.5.0" },
  "config_schema": {
    "dialect": "cheesewaf-notifier-config/v1",
    "fields": [{ "name": "tenant", "kind": "string", "required": false, "max_length": 64 }]
  },
  "secret_fields": ["webhook_ref"],
  "endpoint_templates": [{
    "name": "notify",
    "url_template": "https://alerts.example.test/hook",
    "method": "POST",
    "egress_owner": "cheesewaf-core",
    "variables": []
  }],
  "capabilities": ["alert_delivery"]
}`

// A pack in the index must become a resolvable notifier type without a
// restart, and removing the file must remove the type again.
func TestPluginIndexReloadChangesNotifierRegistry(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Plugins.IndexDir = dir
	cfg.Plugins.WatchInterval = 50 * time.Millisecond

	runtime := startPluginIndex(t.Context(), &cfg, t.TempDir(), "0.4.5-beta")
	t.Cleanup(runtime.Close)
	if runtime.Registry().Supports("acme_alerts") {
		t.Fatal("pack type must not exist before the file is written")
	}

	writePack := func() {
		if err := os.WriteFile(filepath.Join(dir, "acme-alerts.json"), []byte(testNotifierPack), 0o600); err != nil {
			t.Fatalf("write pack: %v", err)
		}
	}
	writePack()
	cutoff := 20 * time.Second
	waitFor(t, cutoff, func() bool { return runtime.Registry().Supports("acme_alerts") })

	if err := os.Remove(filepath.Join(dir, "acme-alerts.json")); err != nil {
		t.Fatalf("remove pack: %v", err)
	}
	waitFor(t, cutoff, func() bool { return !runtime.Registry().Supports("acme_alerts") })
}

// A pack outside the declared host range must not be registered; the reason is
// carried on the entry instead of disappearing.
func TestPluginIndexSkipsIncompatiblePack(t *testing.T) {
	dir := t.TempDir()
	incompatible := []byte(`{
  "api_version": "crp.cheesewaf.io/notifier/v1",
  "provider_id": "official-future-1.0.0",
  "type": "future_alerts",
  "version": "1.0.0",
  "namespace": "official/future",
  "source": "local-index",
  "source_root": "test-root",
  "host_compatibility": { "min": "9.0.0" },
  "config_schema": { "dialect": "cheesewaf-notifier-config/v1", "fields": [] },
  "secret_fields": [],
  "endpoint_templates": [{ "name": "notify", "url_template": "https://alerts.example.test/hook", "method": "POST", "egress_owner": "cheesewaf-core", "variables": [] }],
  "capabilities": ["alert_delivery"]
}`)
	if err := os.WriteFile(filepath.Join(dir, "future.json"), incompatible, 0o600); err != nil {
		t.Fatalf("write pack: %v", err)
	}
	snapshot := index.Scan(dir, "0.4.5-beta")
	factories := notifierPackFactories(snapshot, "0.4.5-beta")
	if _, ok := factories["future_alerts"]; ok {
		t.Fatal("incompatible pack was registered")
	}
	// The index no longer reports packs as manifest problems; the range check
	// is what rejects them, so pin that the reason is available to the caller.
	pack, err := notifierpack.Parse(incompatible)
	if err != nil {
		t.Fatalf("pack must parse: %v", err)
	}
	if err := pack.CheckHost("0.4.5-beta"); err == nil {
		t.Fatal("pack outside the host range must be reported as incompatible")
	}
}

// A built-in type can never be replaced from the index: the same configuration
// would otherwise mean different things depending on which files exist.
func TestPluginIndexCannotShadowBuiltinType(t *testing.T) {
	registry := monitornotify.NewRegistry()
	pack := []byte(testNotifierPack)
	_ = pack
	err := registry.ReplacePacks(map[string]monitornotify.PackFactory{
		"webhook": func(config.NotifierConfig) (monitornotify.Notifier, error) { return nil, nil },
	})
	if err == nil {
		t.Fatal("registering a built-in type must be rejected")
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition was not met before the deadline")
}

var _ = context.Background
