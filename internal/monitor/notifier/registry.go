package notifier

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// Provider is one compiled-in notifier implementation.
type Provider struct {
	Type string
	New  func(config.NotifierConfig, *http.Client) Notifier
}

// BuiltinProviders returns the compiled-in table. The slice is a copy.
func BuiltinProviders() []Provider {
	return []Provider{
		{Type: "webhook", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return NewWebhook(cfg, client)
		}},
		{Type: "email", New: func(cfg config.NotifierConfig, _ *http.Client) Notifier {
			return newEmailNotifier(cfg)
		}},
		{Type: "telegram", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newTelegramNotifier(cfg, client)
		}},
		{Type: "dingtalk", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newDingTalkNotifier(cfg, client)
		}},
		{Type: "wecom", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newWeComNotifier(cfg, client)
		}},
		{Type: "feishu", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newFeishuNotifier(cfg, client)
		}},
		{Type: "datadog", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newDatadogNotifier(cfg, client)
		}},
		{Type: "grafana", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newGrafanaNotifier(cfg, client)
		}},
		{Type: "flashcat", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newFlashcatNotifier(cfg, client)
		}},
		{Type: "nightingale", New: func(cfg config.NotifierConfig, client *http.Client) Notifier {
			return newNightingaleNotifier(cfg, client)
		}},
	}
}

// PackFactory builds a notifier from a declarative pack for one type.
type PackFactory func(config.NotifierConfig) (Notifier, error)

// Registry resolves a notifier type to an implementation: compiled-in first,
// then registered packs. Unknown types are errors, never a webhook fallback.
type Registry struct {
	builtins map[string]Provider
	packs    map[string]PackFactory
	mu       sync.RWMutex
	// generation changes whenever the pack table changes, so consumers can
	// cache what they built without rebuilding on every send.
	generation uint64
}

func NewRegistry() *Registry {
	builtins := BuiltinProviders()
	registry := &Registry{
		builtins: make(map[string]Provider, len(builtins)),
		packs:    make(map[string]PackFactory),
	}
	for _, provider := range builtins {
		registry.builtins[provider.Type] = provider
	}
	return registry
}

// ReplacePacks swaps the whole pack table, which is how a plugin-index reload
// takes effect without rebuilding the registry the manager holds. A factory for
// a built-in type is rejected for the same reason RegisterPack rejects it.
func (r *Registry) ReplacePacks(factories map[string]PackFactory) error {
	if r == nil {
		return fmt.Errorf("notifier registry is unavailable")
	}
	next := make(map[string]PackFactory, len(factories))
	for typeName, factory := range factories {
		normalized := strings.ToLower(strings.TrimSpace(typeName))
		if normalized == "" {
			return fmt.Errorf("notifier pack type is empty")
		}
		if factory == nil {
			return fmt.Errorf("notifier pack %q has no factory", typeName)
		}
		if _, builtin := r.builtins[normalized]; builtin {
			return fmt.Errorf("notifier type %q is already a builtin type", typeName)
		}
		next[normalized] = factory
	}
	r.mu.Lock()
	r.packs = next
	r.generation++
	r.mu.Unlock()
	return nil
}

// Generation reports the current pack table version. It only increases, so a
// cached build can be reused until it changes.
func (r *Registry) Generation() uint64 {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.generation
}

// RegisterPack adds a factory for a type that is not compiled in. A pack may
// not shadow a built-in type: the same configuration would otherwise mean
// different things depending on which packs a binary happened to load.
func (r *Registry) RegisterPack(typeName string, factory PackFactory) error {
	normalized := normalizeNotifierType(typeName)
	if normalized == "" {
		return fmt.Errorf("notifier pack type is required")
	}
	if _, exists := r.builtins[normalized]; exists {
		return fmt.Errorf("notifier pack type %q is already a builtin type", normalized)
	}
	if factory == nil {
		return fmt.Errorf("notifier pack type %q has no factory", normalized)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.packs[normalized]; exists {
		return fmt.Errorf("notifier pack type %q is already registered", normalized)
	}
	r.packs[normalized] = factory
	r.generation++
	return nil
}

func (r *Registry) New(cfg config.NotifierConfig, client *http.Client) (Notifier, error) {
	normalized := normalizeNotifierType(cfg.Type)
	if provider, exists := r.builtins[normalized]; exists {
		return provider.New(cfg, client), nil
	}
	r.mu.RLock()
	factory, exists := r.packs[normalized]
	r.mu.RUnlock()
	if exists {
		return factory(cfg)
	}
	return nil, fmt.Errorf("notifier %q has unsupported type %q", cfg.ID, cfg.Type)
}

func (r *Registry) Supports(typeName string) bool {
	normalized := normalizeNotifierType(typeName)
	if _, exists := r.builtins[normalized]; exists {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.packs[normalized]
	return exists
}

func normalizeNotifierType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
