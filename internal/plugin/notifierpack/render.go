package notifierpack

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// configValue maps a declared config field to the operator-provided value.
// Token and headers are deliberately absent: a URL template is pack-controlled,
// so letting it read credentials would move secrets into a place that proxies,
// logs and browser history all record.
func configValue(name string, cfg config.NotifierConfig) (string, bool) {
	switch name {
	case "endpoint":
		return cfg.Endpoint, true
	case "to":
		return cfg.To, true
	case "msg_type":
		return cfg.MsgType, true
	case "at_mobiles":
		return strings.Join(cfg.AtMobiles, ","), len(cfg.AtMobiles) > 0
	case "smtp_host":
		return cfg.SMTPHost, true
	case "smtp_port":
		if cfg.SMTPPort <= 0 {
			return "", false
		}
		return strconv.Itoa(cfg.SMTPPort), true
	case "smtp_username":
		return cfg.SMTPUsername, true
	case "tls_mode":
		return cfg.TLSMode, true
	case "from":
		return cfg.From, true
	case "subject_prefix":
		return cfg.SubjectPrefix, true
	}
	// Values declared by the pack's config_schema come from the operator's
	// config map. Secrets are not readable here: they are injected as headers
	// at delivery time and never rendered into a URL.
	if value, ok := cfg.Config[name]; ok {
		return value, true
	}
	return "", false
}

// endpointFor picks the URL for one template. An explicit cfg.Endpoint only
// applies to templates without variables, so it can never be spliced into a
// pack-authored path; it is operator config, not pack content, and therefore
// may name a different host.
func (p Pack) endpointFor(template EndpointTemplate, cfg config.NotifierConfig) (string, error) {
	if len(template.Variables) == 0 {
		if override := strings.TrimSpace(cfg.Endpoint); override != "" {
			return validateEndpointOverride(override)
		}
	}
	return renderURL(template, p, cfg)
}

func validateEndpointOverride(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("endpoint override: %v", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("endpoint override %q must use https", raw)
	}
	if parsed.User != nil {
		return "", errors.New("endpoint override must not carry credentials")
	}
	if parsed.Hostname() == "" {
		return "", errors.New("endpoint override must name a host")
	}
	return parsed.String(), nil
}

// renderURL substitutes the template variables and then proves the result still
// points at the template's host. A substituted value could otherwise rewrite
// the authority and turn a trusted pack into an open redirect for alerts.
func renderURL(template EndpointTemplate, pack Pack, cfg config.NotifierConfig) (string, error) {
	rendered, err := renderTemplate(template, pack, cfg)
	if err != nil {
		return "", err
	}
	templateURL, err := url.Parse(template.URLTemplate)
	if err != nil {
		return "", fmt.Errorf("endpoint template %q: %v", template.Name, err)
	}
	renderedURL, err := url.Parse(rendered)
	if err != nil {
		return "", fmt.Errorf("endpoint template %q rendered an invalid URL: %v", template.Name, err)
	}
	if err := checkRenderedURL(templateURL, renderedURL); err != nil {
		return "", fmt.Errorf("endpoint template %q: %w", template.Name, err)
	}
	return renderedURL.String(), nil
}

func renderTemplate(template EndpointTemplate, pack Pack, cfg config.NotifierConfig) (string, error) {
	fields := make(map[string]Field, len(pack.ConfigSchema.Fields))
	for _, field := range pack.ConfigSchema.Fields {
		fields[field.Name] = field
	}
	secrets := make(map[string]struct{}, len(pack.SecretFields))
	for _, name := range pack.SecretFields {
		secrets[name] = struct{}{}
	}
	var builder strings.Builder
	rest := template.URLTemplate
	for {
		start := strings.IndexByte(rest, '{')
		if start < 0 {
			builder.WriteString(rest)
			break
		}
		builder.WriteString(rest[:start])
		end := strings.IndexByte(rest[start:], '}')
		if end < 0 {
			return "", fmt.Errorf("endpoint template %q has an unterminated placeholder", template.Name)
		}
		name := rest[start+1 : start+end]
		rest = rest[start+end+1:]
		if _, secret := secrets[name]; secret {
			return "", fmt.Errorf("endpoint template %q renders secret field %q into the URL; credentials are injected as headers only", template.Name, name)
		}
		field, ok := fields[name]
		if !ok {
			return "", fmt.Errorf("endpoint template %q uses undeclared variable %q", template.Name, name)
		}
		value, present := configValue(name, cfg)
		if !present || value == "" {
			if field.Required {
				return "", fmt.Errorf("endpoint template %q needs required config value %q", template.Name, name)
			}
			continue
		}
		if field.MaxLength > 0 && len(value) > field.MaxLength {
			return "", fmt.Errorf("config value for %q exceeds max_length %d", name, field.MaxLength)
		}
		if hasUnsafeURLRunes(value) {
			return "", fmt.Errorf("config value for %q contains whitespace or control characters", name)
		}
		builder.WriteString(value)
	}
	rendered := builder.String()
	if strings.ContainsAny(rendered, "{}") {
		return "", fmt.Errorf("endpoint template %q rendered unresolved braces", template.Name)
	}
	return rendered, nil
}

func hasUnsafeURLRunes(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\\' {
			return true
		}
	}
	return false
}

func checkRenderedURL(template, rendered *url.URL) error {
	if !strings.EqualFold(rendered.Scheme, "https") {
		return fmt.Errorf("rendered URL scheme %q must be https", rendered.Scheme)
	}
	if rendered.User != nil {
		return errors.New("rendered URL must not carry user info")
	}
	if rendered.Fragment != "" {
		return errors.New("rendered URL must not carry a fragment")
	}
	if !strings.EqualFold(rendered.Hostname(), template.Hostname()) {
		return fmt.Errorf("rendered host %q differs from template host %q", rendered.Hostname(), template.Hostname())
	}
	if normalizedPort(rendered) != normalizedPort(template) {
		return fmt.Errorf("rendered port %q differs from template port %q", normalizedPort(rendered), normalizedPort(template))
	}
	return nil
}

func normalizedPort(parsed *url.URL) string {
	port := parsed.Port()
	if port == "443" {
		return ""
	}
	return port
}
