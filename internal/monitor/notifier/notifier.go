package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	manager := &Manager{}
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		notifier, err := NewProvider(cfg, nil)
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

// NewProvider creates the notifier implementation selected by cfg.Type.
// Unknown provider types are rejected instead of falling back to a generic
// webhook, so a typo cannot silently deliver alerts to the wrong endpoint.
func NewProvider(cfg config.NotifierConfig, client *http.Client) (Notifier, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Type)) {
	case "webhook":
		return NewWebhook(cfg, client), nil
	case "dingtalk":
		return newDingTalkNotifier(cfg, client), nil
	case "feishu":
		return newFeishuNotifier(cfg, client), nil
	case "wecom":
		return newWeComNotifier(cfg, client), nil
	case "telegram":
		return newTelegramNotifier(cfg, client), nil
	case "email":
		return newEmailNotifier(cfg), nil
	default:
		return nil, fmt.Errorf("notifier %q has unsupported type %q", cfg.ID, cfg.Type)
	}
}

func errorsJoin(values []error) error {
	return errors.Join(values...)
}
