package notifier

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

type packNotifier struct {
	typeName string
}

func (p packNotifier) Notify(context.Context, monitor.Alert) error { return nil }

func TestEveryConfiguredNotifierTypeHasImplementation(t *testing.T) {
	configured := config.NotifierTypes()
	if !slices.IsSorted(configured) {
		t.Fatalf("config.NotifierTypes() must be sorted, got %v", configured)
	}

	registry := NewRegistry()
	for _, typeName := range configured {
		if !registry.Supports(typeName) {
			t.Fatalf("configured notifier type %q has no compiled-in implementation", typeName)
		}
		if _, err := registry.New(config.NotifierConfig{ID: typeName, Type: typeName}, nil); err != nil {
			t.Fatalf("registry cannot build configured notifier type %q: %v", typeName, err)
		}
	}

	builtins := BuiltinProviders()
	if len(builtins) != len(configured) {
		t.Fatalf("compiled-in providers (%d) and configured types (%d) differ: %v", len(builtins), len(configured), configured)
	}
	for _, provider := range builtins {
		if !slices.Contains(configured, provider.Type) {
			t.Fatalf("compiled-in provider %q is not accepted by configuration validation", provider.Type)
		}
	}
}

func TestRegistryRejectsUnknownType(t *testing.T) {
	registry := NewRegistry()
	if registry.Supports("pagerduty") {
		t.Fatal("unregistered type must not be supported")
	}
	if _, err := registry.New(config.NotifierConfig{ID: "pager", Type: "pagerduty"}, nil); err == nil ||
		!strings.Contains(err.Error(), `notifier "pager" has unsupported type "pagerduty"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegistryResolvesPackType(t *testing.T) {
	registry := NewRegistry()
	if err := registry.RegisterPack("pagerduty", func(cfg config.NotifierConfig) (Notifier, error) {
		return packNotifier{typeName: cfg.Type}, nil
	}); err != nil {
		t.Fatalf("register pack type: %v", err)
	}
	if !registry.Supports("pagerduty") {
		t.Fatal("registered pack type must be supported")
	}

	built, err := registry.New(config.NotifierConfig{ID: "pager", Type: "pagerduty"}, nil)
	if err != nil {
		t.Fatalf("build pack notifier: %v", err)
	}
	packed, ok := built.(packNotifier)
	if !ok || packed.typeName != "pagerduty" {
		t.Fatalf("pack notifier not resolved: %#v", built)
	}
}

func TestRegistryRejectsDuplicatePackRegistration(t *testing.T) {
	registry := NewRegistry()
	factory := func(config.NotifierConfig) (Notifier, error) { return packNotifier{}, nil }
	if err := registry.RegisterPack("pagerduty", factory); err != nil {
		t.Fatalf("register pack type: %v", err)
	}
	if err := registry.RegisterPack("PagerDuty", factory); err == nil ||
		!strings.Contains(err.Error(), "already registered") {
		t.Fatalf("duplicate pack registration must fail, got %v", err)
	}
}

func TestRegistryPackCannotOverrideBuiltin(t *testing.T) {
	registry := NewRegistry()
	err := registry.RegisterPack("webhook", func(config.NotifierConfig) (Notifier, error) {
		return packNotifier{typeName: "webhook"}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "already a builtin type") {
		t.Fatalf("pack overriding a builtin must fail, got %v", err)
	}

	built, err := registry.New(config.NotifierConfig{ID: "hook", Type: "webhook"}, nil)
	if err != nil {
		t.Fatalf("build builtin notifier: %v", err)
	}
	if _, ok := built.(*Webhook); !ok {
		t.Fatalf("builtin must win over packs, got %#v", built)
	}
}

func TestRegistryNormalizesTypeNames(t *testing.T) {
	registry := NewRegistry()
	if !registry.Supports("  WebHook ") {
		t.Fatal("type lookup must ignore case and surrounding space")
	}
}

type countingNotifier struct{ calls int }

func (n *countingNotifier) Notify(context.Context, monitor.Alert) error { n.calls++; return nil }

// A pack reload replaces the registry factories while the alert loop keeps
// running, so the manager must resolve providers per send instead of holding
// the instances built at startup.
func TestManagerUsesCurrentRegistryForEachSend(t *testing.T) {
	cfg := config.NotifierConfig{ID: "pack", Type: "pack_type", Endpoint: "https://example.test/hook", Enabled: true}
	registry := NewRegistry()
	first := &countingNotifier{}
	if err := registry.RegisterPack("pack_type", func(config.NotifierConfig) (Notifier, error) { return first, nil }); err != nil {
		t.Fatalf("register: %v", err)
	}
	manager := NewManagerWithRegistry([]config.NotifierConfig{cfg}, registry)
	alert := monitor.Alert{RuleID: "r", Name: "n"}

	if err := manager.Notify(context.Background(), []monitor.Alert{alert}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if first.calls != 1 {
		t.Fatalf("first provider calls = %d", first.calls)
	}

	second := &countingNotifier{}
	if err := registry.ReplacePacks(map[string]PackFactory{
		"pack_type": func(config.NotifierConfig) (Notifier, error) { return second, nil },
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := manager.Notify(context.Background(), []monitor.Alert{alert}); err != nil {
		t.Fatalf("second send: %v", err)
	}
	if second.calls != 1 || first.calls != 1 {
		t.Fatalf("after reload: first=%d second=%d, want 1/1", first.calls, second.calls)
	}
}

// Rebuilding providers on every send would drop connection reuse. The manager
// caches the instances until the registry generation changes.
func TestManagerReusesProvidersUntilRegistryChanges(t *testing.T) {
	cfg := config.NotifierConfig{ID: "pack", Type: "cached_type", Endpoint: "https://example.test/hook", Enabled: true}
	registry := NewRegistry()
	built := 0
	if err := registry.RegisterPack("cached_type", func(config.NotifierConfig) (Notifier, error) {
		built++
		return &countingNotifier{}, nil
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	manager := NewManagerWithRegistry([]config.NotifierConfig{cfg}, registry)
	alert := monitor.Alert{RuleID: "r", Name: "n"}
	for i := 0; i < 3; i++ {
		if err := manager.Notify(context.Background(), []monitor.Alert{alert}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if built != 1 {
		t.Fatalf("provider built %d times without a registry change", built)
	}
	if err := registry.ReplacePacks(map[string]PackFactory{
		"cached_type": func(config.NotifierConfig) (Notifier, error) {
			built++
			return &countingNotifier{}, nil
		},
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := manager.Notify(context.Background(), []monitor.Alert{alert}); err != nil {
		t.Fatalf("send after reload: %v", err)
	}
	if built != 2 {
		t.Fatalf("provider built %d times, want a rebuild after the reload", built)
	}
}

// A reload that lands while providers are being built must not be cached under
// the newer generation: the recorded generation is the one read before the
// build, so the next send rebuilds.
func TestManagerDoesNotCacheAcrossReloadDuringBuild(t *testing.T) {
	cfg := config.NotifierConfig{ID: "pack", Type: "race_type", Endpoint: "https://example.test/hook", Enabled: true}
	registry := NewRegistry()
	var reloaded bool
	if err := registry.RegisterPack("race_type", func(config.NotifierConfig) (Notifier, error) {
		if !reloaded {
			reloaded = true
			if err := registry.ReplacePacks(map[string]PackFactory{
				"race_type": func(config.NotifierConfig) (Notifier, error) { return &countingNotifier{}, nil },
			}); err != nil {
				t.Fatalf("replace during build: %v", err)
			}
		}
		return &countingNotifier{}, nil
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Construct directly so the first build happens inside Notify; a manager
	// built by the constructor would already consume the reload.
	manager := &Manager{configs: []config.NotifierConfig{cfg}, registry: registry}
	alert := monitor.Alert{RuleID: "r", Name: "n"}
	if err := manager.Notify(context.Background(), []monitor.Alert{alert}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if manager.builtFor == registry.Generation() {
		t.Fatal("a reload during the build was cached as current")
	}
	if err := manager.Notify(context.Background(), []monitor.Alert{alert}); err != nil {
		t.Fatalf("send after reload: %v", err)
	}
	if manager.builtFor != registry.Generation() {
		t.Fatalf("cache did not catch up: builtFor=%d generation=%d", manager.builtFor, registry.Generation())
	}
}
