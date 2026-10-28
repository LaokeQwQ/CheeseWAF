package notifier

import (
	"context"
	"errors"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

type Notifier interface {
	Notify(ctx context.Context, alert monitor.Alert) error
}

type Manager struct {
	mu       sync.Mutex
	configs  []config.NotifierConfig
	registry *Registry
	// builtFor is the registry generation the cached instances were built for.
	builtFor     uint64
	built        bool
	cached       []Notifier
	cachedErrors []error
	// notifiers and configErrors are the startup snapshot. Notify resolves the
	// configurations again so a plugin-index reload reaches the alert loop.
	notifiers    []Notifier
	configErrors []error
}

func NewManager(configs []config.NotifierConfig) *Manager {
	return NewManagerWithRegistry(configs, nil)
}

// NewManagerWithRegistry lets the caller share one registry with the rest of
// the process, so a plugin-index reload reaches every notifier the manager
// builds afterwards. A nil registry uses the compiled-in providers only.
func NewManagerWithRegistry(configs []config.NotifierConfig, registry *Registry) *Manager {
	if registry == nil {
		registry = NewRegistry()
	}
	manager := &Manager{
		configs:  append([]config.NotifierConfig(nil), configs...),
		registry: registry,
	}
	manager.notifiers, manager.configErrors = manager.resolve()
	return manager
}

// resolve builds the current notifier instances from the shared registry. It
// runs on every Notify because a pack reload replaces the registry's factories
// while the alert loop keeps running.
func (m *Manager) resolve() ([]Notifier, []error) {
	if m == nil {
		return nil, nil
	}
	// A manager built without a registry (tests, embedders) already holds the
	// instances it wants; there is no factory source to re-resolve from.
	if m.registry == nil {
		return m.notifiers, m.configErrors
	}
	registry := m.registry
	// Read the generation before building. If a reload lands while the
	// providers are being constructed, the recorded generation stays behind
	// and the next call rebuilds instead of caching stale instances.
	generation := registry.Generation()
	m.mu.Lock()
	if m.built && m.builtFor == generation {
		notifiers, cachedErrors := m.cached, m.cachedErrors
		m.mu.Unlock()
		return notifiers, cachedErrors
	}
	m.mu.Unlock()
	notifiers := make([]Notifier, 0, len(m.configs))
	configErrors := make([]error, 0)
	for _, cfg := range m.configs {
		if !cfg.Enabled {
			continue
		}
		notifier, err := registry.New(cfg, nil)
		if err != nil {
			configErrors = append(configErrors, err)
			continue
		}
		notifiers = append(notifiers, notifier)
	}
	m.mu.Lock()
	m.built = true
	m.builtFor = generation
	m.cached = notifiers
	m.cachedErrors = configErrors
	m.mu.Unlock()
	return notifiers, configErrors
}

func (m *Manager) Notify(ctx context.Context, alerts []monitor.Alert) error {
	if m == nil {
		return nil
	}
	notifiers, configErrors := m.resolve()
	deliveryErrors := make([]error, 0, len(configErrors))
	deliveryErrors = append(deliveryErrors, configErrors...)
	for _, alert := range alerts {
		for _, notifier := range notifiers {
			if err := notifier.Notify(ctx, alert); err != nil {
				deliveryErrors = append(deliveryErrors, err)
			}
		}
	}
	return errors.Join(deliveryErrors...)
}

func errorsJoin(values []error) error {
	return errors.Join(values...)
}
