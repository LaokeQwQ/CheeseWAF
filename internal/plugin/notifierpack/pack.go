// Package notifierpack loads declarative notification provider packs.
//
// A pack says where an alert goes and which operator-provided values fill the
// URL; it ships no code, opens no connection of its own, and holds no
// credentials. Egress and secret injection stay in the core so that dropping a
// third-party pack into a host cannot turn it into an arbitrary network client
// or a credential store.
package notifierpack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

const (
	// APIVersion is the pack document version this host understands.
	APIVersion = "crp.cheesewaf.io/notifier/v1"
	// ConfigSchemaDialect is the only field-shape dialect understood here.
	ConfigSchemaDialect = "cheesewaf-notifier-config/v1"

	notifyTemplateName = "notify"
	egressOwner        = "cheesewaf-core"
)

// ErrUnsupported marks a pack this host cannot load: either it targets a
// provider type the core already implements, or the running host version is
// outside the range the pack declares.
var ErrUnsupported = errors.New("unsupported notifier pack")

// ErrInvalidPack marks a pack that violates the notifier pack contract.
var ErrInvalidPack = errors.New("invalid notifier pack")

// Field declares one operator-supplied value a pack's URL template may use.
type Field struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Required  bool   `json:"required"`
	MaxLength int    `json:"max_length,omitempty"`
}

// EndpointTemplate is the only network knowledge a pack carries: a URL shape
// whose host is fixed at load time and whose variables come from the notifier
// config.
type EndpointTemplate struct {
	Name        string   `json:"name"`
	URLTemplate string   `json:"url_template"`
	Method      string   `json:"method"`
	EgressOwner string   `json:"egress_owner"`
	Variables   []string `json:"variables"`
}

// Pack is one decoded notifier pack document.
type Pack struct {
	APIVersion        string                `json:"api_version"`
	ProviderID        string                `json:"provider_id"`
	Type              string                `json:"type"`
	Version           string                `json:"version"`
	Namespace         string                `json:"namespace"`
	Source            string                `json:"source"`
	SourceRoot        string                `json:"source_root"`
	HostCompatibility crp.HostCompatibility `json:"host_compatibility,omitempty"`
	ConfigSchema      struct {
		Dialect string  `json:"dialect"`
		Fields  []Field `json:"fields"`
	} `json:"config_schema"`
	SecretFields      []string           `json:"secret_fields"`
	EndpointTemplates []EndpointTemplate `json:"endpoint_templates"`
	Capabilities      []string           `json:"capabilities"`
}

const (
	maxProviderIDLength  = 128
	maxPackPathLength    = 128
	maxTypeLength        = 64
	maxFields            = 24
	maxFieldNameLength   = 64
	maxFieldKindLength   = 32
	maxFieldLength       = 2048
	maxSecretFields      = 16
	maxEndpointTemplates = 4
	maxURLTemplateLength = 512
	maxCapabilities      = 2
)

var (
	providerIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	typePattern         = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	versionPattern      = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
	boundPattern        = regexp.MustCompile(`^[vV]?[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	fieldNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	secretNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*_ref$`)
	templateNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	// A 32+ character alphanumeric run is what embedded API keys and hook IDs
	// look like. Packs must point at operator config instead of carrying them.
	highEntropyPattern = regexp.MustCompile(`[A-Za-z0-9]{32,}`)
)

// isCoreProviderType reports whether the core already implements the type. The
// list comes from config.NotifierTypes so a new built-in cannot be forgotten
// here and silently shadowed by a pack.
func isCoreProviderType(value string) bool {
	for _, builtin := range config.NotifierTypes() {
		if strings.EqualFold(builtin, value) {
			return true
		}
	}
	return false
}

// Parse strictly decodes and validates one pack. Unknown fields are rejected
// so a misspelled security key cannot be silently ignored.
func Parse(data []byte) (Pack, error) {
	if err := scanRejectedFields(data); err != nil {
		return Pack{}, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return Pack{}, fmt.Errorf("%w: pack document is empty", ErrInvalidPack)
	}
	var pack Pack
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pack); err != nil {
		return Pack{}, fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Pack{}, fmt.Errorf("%w: trailing JSON data", ErrInvalidPack)
		}
		return Pack{}, fmt.Errorf("%w: invalid trailing JSON: %v", ErrInvalidPack, err)
	}
	if err := pack.Validate(); err != nil {
		return Pack{}, err
	}
	return pack, nil
}

// CheckHost verifies the pack's host compatibility range.
func (p Pack) CheckHost(hostVersion string) error {
	if err := p.HostCompatibility.Check(hostVersion); err != nil {
		// Both markers stay reachable: callers filter on ErrUnsupported, while
		// operators reading the message need the failing bound.
		return fmt.Errorf("%w: provider %q: %w", ErrUnsupported, p.ProviderID, err)
	}
	return nil
}

// Validate checks the pack against the notifier pack contract. New calls it
// again so a Pack assembled in memory cannot bypass the gates Parse applied.
func (p Pack) Validate() error {
	if p.APIVersion != APIVersion {
		return fmt.Errorf("%w: api_version %q, want %q", ErrInvalidPack, p.APIVersion, APIVersion)
	}
	if !providerIDPattern.MatchString(p.ProviderID) || len(p.ProviderID) > maxProviderIDLength {
		return fmt.Errorf("%w: provider_id %q must be 1..128 characters of letters, digits, '.', '_' or '-' and start with a letter or digit", ErrInvalidPack, p.ProviderID)
	}
	if err := validateType(p.Type); err != nil {
		return err
	}
	if !versionPattern.MatchString(p.Version) {
		return fmt.Errorf("%w: version %q must be dotted numeric version text such as \"1.2.0\"", ErrInvalidPack, p.Version)
	}
	// Bounds are checked here so a typo fails at load instead of on the first
	// delivery attempt.
	for _, bound := range []struct{ name, value string }{
		{"min", p.HostCompatibility.Min},
		{"max", p.HostCompatibility.Max},
	} {
		value := strings.TrimSpace(bound.value)
		if value == "" {
			continue
		}
		if !boundPattern.MatchString(value) {
			return fmt.Errorf("%w: host_compatibility.%s %q must be dotted numeric version text", ErrInvalidPack, bound.name, bound.value)
		}
	}
	for _, text := range []struct{ label, value string }{
		{"namespace", p.Namespace},
		{"source", p.Source},
		{"source_root", p.SourceRoot},
	} {
		if err := validatePathText(text.label, text.value); err != nil {
			return err
		}
	}
	if err := p.validateConfigSchema(); err != nil {
		return err
	}
	if err := p.validateSecretFields(); err != nil {
		return err
	}
	if err := p.validateEndpointTemplates(); err != nil {
		return err
	}
	return validateCapabilities(p.Capabilities)
}

func validateType(value string) error {
	if value == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidPack)
	}
	if len(value) > maxTypeLength || !typePattern.MatchString(value) {
		return fmt.Errorf("%w: type %q must be 1..64 lowercase letters, digits or '.', '_', '-' separators", ErrInvalidPack, value)
	}
	if isCoreProviderType(value) {
		return fmt.Errorf("%w: type %q is delivered by the core notifier; a pack may only add provider types the core does not own", ErrUnsupported, value)
	}
	return nil
}

func validatePathText(label, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidPack, label)
	}
	if len(value) > maxPackPathLength {
		return fmt.Errorf("%w: %s %q exceeds %d characters", ErrInvalidPack, label, value, maxPackPathLength)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s %q must not have leading or trailing whitespace", ErrInvalidPack, label, value)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("%w: %s %q must not contain %q", ErrInvalidPack, label, value, "..")
	}
	for _, r := range value {
		// Backslash is a separator on some hosts, so "..\" and friends must not
		// slip past the traversal check above.
		if r < 0x20 || r == 0x7f || r == '\\' {
			return fmt.Errorf("%w: %s %q must not contain control characters or backslashes", ErrInvalidPack, label, value)
		}
	}
	return nil
}

func (p Pack) validateConfigSchema() error {
	if p.ConfigSchema.Dialect != ConfigSchemaDialect {
		return fmt.Errorf("%w: config_schema.dialect %q, want %q", ErrInvalidPack, p.ConfigSchema.Dialect, ConfigSchemaDialect)
	}
	if len(p.ConfigSchema.Fields) > maxFields {
		return fmt.Errorf("%w: config_schema has %d fields, limit is %d", ErrInvalidPack, len(p.ConfigSchema.Fields), maxFields)
	}
	seen := make(map[string]struct{}, len(p.ConfigSchema.Fields))
	for _, field := range p.ConfigSchema.Fields {
		if field.Name == "" || len(field.Name) > maxFieldNameLength || !fieldNamePattern.MatchString(field.Name) {
			return fmt.Errorf("%w: config field name %q must be 1..64 lowercase letters, digits or single '_' separators", ErrInvalidPack, field.Name)
		}
		if _, duplicate := seen[field.Name]; duplicate {
			return fmt.Errorf("%w: duplicate config field %q", ErrInvalidPack, field.Name)
		}
		seen[field.Name] = struct{}{}
		// Free-form config values reach URL templates, so a non-secret field
		// may never borrow the secret-reference suffix: a credential reference
		// belongs in secret_fields and stays out of URLs by construction.
		if strings.HasSuffix(field.Name, "_ref") {
			return fmt.Errorf("%w: config field %q must not use the \"_ref\" suffix reserved for secret_fields", ErrInvalidPack, field.Name)
		}
		if field.Kind == "" || len(field.Kind) > maxFieldKindLength || !fieldNamePattern.MatchString(field.Kind) {
			return fmt.Errorf("%w: config field %q kind %q must be 1..32 lowercase letters, digits or single '_' separators", ErrInvalidPack, field.Name, field.Kind)
		}
		if field.MaxLength < 0 || field.MaxLength > maxFieldLength {
			return fmt.Errorf("%w: config field %q max_length %d must be 0..%d", ErrInvalidPack, field.Name, field.MaxLength, maxFieldLength)
		}
	}
	return nil
}

func (p Pack) validateSecretFields() error {
	if len(p.SecretFields) > maxSecretFields {
		return fmt.Errorf("%w: %d secret_fields declared, limit is %d", ErrInvalidPack, len(p.SecretFields), maxSecretFields)
	}
	declared := make(map[string]struct{}, len(p.SecretFields))
	for _, name := range p.SecretFields {
		if len(name) > maxFieldNameLength || !secretNamePattern.MatchString(name) {
			return fmt.Errorf("%w: secret field %q must be a lowercase snake_case reference name ending in \"_ref\"", ErrInvalidPack, name)
		}
		if _, duplicate := declared[name]; duplicate {
			return fmt.Errorf("%w: duplicate secret field %q", ErrInvalidPack, name)
		}
		declared[name] = struct{}{}
		if highEntropyPattern.MatchString(name) {
			return fmt.Errorf("%w: secret field %q looks like a credential value; packs may only carry reference names", ErrInvalidPack, name)
		}
	}
	return nil
}

func (p Pack) validateEndpointTemplates() error {
	if len(p.EndpointTemplates) == 0 {
		return fmt.Errorf("%w: endpoint_templates is required", ErrInvalidPack)
	}
	if len(p.EndpointTemplates) > maxEndpointTemplates {
		return fmt.Errorf("%w: %d endpoint templates declared, limit is %d", ErrInvalidPack, len(p.EndpointTemplates), maxEndpointTemplates)
	}
	declaredFields := make(map[string]struct{}, len(p.ConfigSchema.Fields))
	for _, field := range p.ConfigSchema.Fields {
		declaredFields[field.Name] = struct{}{}
	}
	for _, name := range p.SecretFields {
		declaredFields[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(p.EndpointTemplates))
	hasNotify := false
	for _, template := range p.EndpointTemplates {
		if template.Name == "" || len(template.Name) > maxFieldNameLength || !templateNamePattern.MatchString(template.Name) {
			return fmt.Errorf("%w: endpoint template name %q must be 1..64 lowercase letters, digits or '.', '_', '-' separators", ErrInvalidPack, template.Name)
		}
		if _, duplicate := seen[template.Name]; duplicate {
			return fmt.Errorf("%w: duplicate endpoint template %q", ErrInvalidPack, template.Name)
		}
		seen[template.Name] = struct{}{}
		if template.Name == notifyTemplateName {
			hasNotify = true
		}
		if template.Method != http.MethodPost {
			return fmt.Errorf("%w: endpoint template %q method %q must be POST", ErrInvalidPack, template.Name, template.Method)
		}
		if template.EgressOwner != egressOwner {
			return fmt.Errorf("%w: endpoint template %q egress_owner %q must be %q; packs cannot own egress", ErrInvalidPack, template.Name, template.EgressOwner, egressOwner)
		}
		if err := validateURLTemplate(template); err != nil {
			return err
		}
		used, err := placeholders(template.URLTemplate)
		if err != nil {
			return fmt.Errorf("%w: endpoint template %q: %v", ErrInvalidPack, template.Name, err)
		}
		declared := make(map[string]struct{}, len(template.Variables))
		for _, variable := range template.Variables {
			if !fieldNamePattern.MatchString(variable) {
				return fmt.Errorf("%w: endpoint template %q variable %q must be a lowercase snake_case name", ErrInvalidPack, template.Name, variable)
			}
			if _, duplicate := declared[variable]; duplicate {
				return fmt.Errorf("%w: endpoint template %q declares variable %q twice", ErrInvalidPack, template.Name, variable)
			}
			declared[variable] = struct{}{}
			if _, ok := declaredFields[variable]; !ok {
				return fmt.Errorf("%w: endpoint template %q variable %q is not declared in config_schema.fields or secret_fields", ErrInvalidPack, template.Name, variable)
			}
		}
		for _, name := range used {
			if _, ok := declared[name]; !ok {
				return fmt.Errorf("%w: endpoint template %q uses variable %q without declaring it in variables", ErrInvalidPack, template.Name, name)
			}
		}
		for name := range declared {
			if !contains(used, name) {
				return fmt.Errorf("%w: endpoint template %q declares variable %q that url_template never uses", ErrInvalidPack, template.Name, name)
			}
		}
	}
	if !hasNotify {
		return fmt.Errorf("%w: endpoint_templates needs one template named %q", ErrInvalidPack, notifyTemplateName)
	}
	return nil
}

func validateURLTemplate(template EndpointTemplate) error {
	raw := template.URLTemplate
	if raw == "" {
		return fmt.Errorf("%w: endpoint template %q url_template is required", ErrInvalidPack, template.Name)
	}
	if len(raw) > maxURLTemplateLength {
		return fmt.Errorf("%w: endpoint template %q url_template exceeds %d characters", ErrInvalidPack, template.Name, maxURLTemplateLength)
	}
	if !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return fmt.Errorf("%w: endpoint template %q url_template must start with https://", ErrInvalidPack, template.Name)
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f || r == ' ' {
			return fmt.Errorf("%w: endpoint template %q url_template must not contain whitespace or control characters", ErrInvalidPack, template.Name)
		}
	}
	if highEntropyPattern.MatchString(raw) {
		return fmt.Errorf("%w: endpoint template %q url_template embeds a 32+ character token; reference an operator config value instead", ErrInvalidPack, template.Name)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: endpoint template %q url_template: %v", ErrInvalidPack, template.Name, err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("%w: endpoint template %q url_template must use https", ErrInvalidPack, template.Name)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: endpoint template %q url_template must not carry credentials", ErrInvalidPack, template.Name)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("%w: endpoint template %q url_template must not carry a fragment", ErrInvalidPack, template.Name)
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("%w: endpoint template %q url_template must name a host", ErrInvalidPack, template.Name)
	}
	return nil
}

func validateCapabilities(capabilities []string) error {
	if len(capabilities) == 0 {
		return fmt.Errorf("%w: capabilities is required", ErrInvalidPack)
	}
	if len(capabilities) > maxCapabilities {
		return fmt.Errorf("%w: %d capabilities declared, limit is %d", ErrInvalidPack, len(capabilities), maxCapabilities)
	}
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		switch capability {
		case "alert_delivery", "test_delivery":
		default:
			return fmt.Errorf("%w: capability %q must be %q or %q", ErrInvalidPack, capability, "alert_delivery", "test_delivery")
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("%w: capability %q declared twice", ErrInvalidPack, capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

// placeholders returns the distinct `{name}` variables a template uses. A
// malformed brace is an error: silently ignoring it would send a literal URL
// that no host check ever validated.
func placeholders(template string) ([]string, error) {
	var names []string
	seen := make(map[string]struct{})
	rest := template
	for {
		start := strings.IndexByte(rest, '{')
		if start < 0 {
			if strings.IndexByte(rest, '}') >= 0 {
				return nil, fmt.Errorf("url_template has an unmatched %q", "}")
			}
			return names, nil
		}
		if strings.IndexByte(rest[:start], '}') >= 0 {
			return nil, fmt.Errorf("url_template has an unmatched %q", "}")
		}
		end := strings.IndexByte(rest[start:], '}')
		if end < 0 {
			return nil, fmt.Errorf("url_template has an unterminated %q", "{")
		}
		name := rest[start+1 : start+end]
		if !fieldNamePattern.MatchString(name) {
			return nil, fmt.Errorf("placeholder %q is not a lowercase snake_case variable name", name)
		}
		if _, duplicate := seen[name]; !duplicate {
			seen[name] = struct{}{}
			names = append(names, name)
		}
		rest = rest[start+end+1:]
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
