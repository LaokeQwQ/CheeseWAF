package notifierpack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/monitor"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

const (
	notifierTimeout = 10 * time.Second
	// Error bodies are read only to explain a failure; a hostile endpoint must
	// not be able to turn that into an unbounded download.
	maxErrorBodyBytes = 4 << 10
)

// Deliverer delivers alerts through one endpoint template rendered from the
// notifier config. It owns no connection and holds no credentials of its own:
// the endpoint is frozen at construction and secrets are read from the
// operator's config, never from the pack.
type Deliverer struct {
	providerID   string
	endpoint     string
	client       *http.Client
	headers      map[string]string
	token        string
	allowPrivate bool
}

// New builds a Deliverer from the pack template named "notify" (or the single
// template when only one exists). cfg.Endpoint may override the template URL
// when the template has no variables; cfg.Token/Headers are never rendered into
// the URL.
func (p Pack) New(cfg config.NotifierConfig, client *http.Client) (*Deliverer, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	template, err := p.notifyTemplate()
	if err != nil {
		return nil, err
	}
	endpoint, err := p.endpointFor(template, cfg)
	if err != nil {
		return nil, fmt.Errorf("notifier pack %q: %w", p.ProviderID, err)
	}
	// Fail at construction when the deployment policy already forbids the
	// endpoint, so a deliverer the host can never use is not built at all.
	if _, err := netguard.ValidateURL(endpoint, endpointPolicy(cfg.AllowPrivateEndpoint)); err != nil {
		return nil, fmt.Errorf("notifier pack %q endpoint: %w", p.ProviderID, err)
	}
	if client == nil {
		client = netguard.NewHTTPClient(netguard.HTTPClientOptions{
			Timeout: notifierTimeout,
			Policy:  endpointPolicy(cfg.AllowPrivateEndpoint),
		})
	}
	headers := make(map[string]string, len(cfg.Headers))
	for key, value := range cfg.Headers {
		headers[key] = value
	}
	return &Deliverer{
		providerID:   p.ProviderID,
		endpoint:     endpoint,
		client:       client,
		headers:      headers,
		token:        cfg.Token,
		allowPrivate: cfg.AllowPrivateEndpoint,
	}, nil
}

func (p Pack) notifyTemplate() (EndpointTemplate, error) {
	for _, template := range p.EndpointTemplates {
		if template.Name == notifyTemplateName {
			return template, nil
		}
	}
	if len(p.EndpointTemplates) == 1 {
		return p.EndpointTemplates[0], nil
	}
	return EndpointTemplate{}, fmt.Errorf("%w: provider %q has no %q endpoint template", ErrInvalidPack, p.ProviderID, notifyTemplateName)
}

// Notify posts the alert to the frozen endpoint. There is no retry loop: the
// caller owns alert fan-out and already schedules the next evaluation, so a
// retry here would duplicate deliveries the alert engine has not deduplicated.
func (d *Deliverer) Notify(ctx context.Context, alert monitor.Alert) error {
	if d == nil || d.endpoint == "" {
		return errors.New("notifier pack deliverer is not configured")
	}
	body, err := json.Marshal(struct {
		Alert monitor.Alert `json:"alert"`
	}{Alert: alert})
	if err != nil {
		return fmt.Errorf("notifier pack %q encode alert: %w", d.providerID, err)
	}
	request, err := netguard.NewRequest(ctx, http.MethodPost, d.endpoint, bytes.NewReader(body), endpointPolicy(d.allowPrivate))
	if err != nil {
		return fmt.Errorf("notifier pack %q request: %w", d.providerID, err)
	}
	for key, value := range d.headers {
		request.Header.Set(key, value)
	}
	if d.token != "" {
		request.Header.Set("Authorization", "Bearer "+d.token)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := d.client.Do(request)
	if err != nil {
		return fmt.Errorf("notifier pack %q delivery failed: %w", d.providerID, err)
	}
	defer netguard.DrainAndClose(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if detail := readErrorBody(response.Body); detail != "" {
			return fmt.Errorf("notifier pack %q returned %s: %s", d.providerID, response.Status, detail)
		}
		return fmt.Errorf("notifier pack %q returned %s", d.providerID, response.Status)
	}
	return nil
}

// endpointPolicy keeps pack egress on https even when the operator allows a
// private endpoint: the scheme gate is about the pack contract, the IP gate is
// about deployment topology.
func endpointPolicy(allowPrivate bool) netguard.URLPolicy {
	return netguard.URLPolicy{
		Purpose:        "notifier pack",
		HostPurpose:    "notifier pack endpoint",
		AllowedSchemes: []string{"https"},
		AllowPrivate:   allowPrivate,
	}
}

func readErrorBody(body io.Reader) string {
	if body == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
