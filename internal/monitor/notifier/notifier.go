package notifier

import (
	"context"
	"errors"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
)

type Notifier interface {
	Notify(ctx context.Context, alert monitor.Alert) error
}

type Manager struct {
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
	manager := &Manager{}
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		notifier, err := registry.New(cfg, nil)
		if err != nil {
			manager.configErrors = append(manager.configErrors, err)
			continue
		}
		manager.notifiers = append(manager.notifiers, notifier)
	}
	return manager
}

func (m *Manager) Notify(ctx context.Context, alerts []monitor.Alert) error {
	if m == nil {
		return nil
	}
	deliveryErrors := make([]error, 0, len(m.configErrors))
	deliveryErrors = append(deliveryErrors, m.configErrors...)
	for _, alert := range alerts {
		for _, notifier := range m.notifiers {
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
