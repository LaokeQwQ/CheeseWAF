package notifierpack

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/netguard"
)

var (
	providerIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	versionPattern     = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)
	fieldNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	endpointNamePatt   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	placeholderPattern = regexp.MustCompile(`\{([a-z][a-z0-9_]{0,63})\}`)
)

var endpointPolicy = netguard.URLPolicy{
	Purpose:        "notification endpoint",
	HostPurpose:    "notification endpoint",
	AllowedSchemes: []string{"https"},
}

var allowedCapabilities = map[Capability]struct{}{
	CapabilitySendText:      {},
	CapabilitySendMarkdown:  {},
	CapabilitySendHTML:      {},
	CapabilitySendCard:      {},
	CapabilityMention:       {},
	CapabilityAttachment:    {},
	CapabilityRetry:         {},
	CapabilityHMACSignature: {},
}

// rejectedHostSuffixes are names that resolve only inside a local network or
// documentation context. They are rejected even though they are not literal
// IP addresses, because a public HTTPS endpoint can never use them.
var rejectedHostSuffixes = []string{
	".localhost",
	".local",
	".localdomain",
	".internal",
	".intranet",
	".lan",
	".corp",
	".home.arpa",
	".test",
	".invalid",
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPack, fmt.Sprintf(format, args...))
}

// Validate checks a pack against the descriptor contract. It does not mutate
// the receiver and does not grant runtime permission.
func (p ProviderPack) Validate() error {
	if p.APIVersion != APIVersion {
		return invalidf("api_version must be %q", APIVersion)
	}
	if len(p.ProviderID) == 0 || len(p.ProviderID) > MaxProviderIDBytes {
		return invalidf("provider_id must be 1-%d bytes", MaxProviderIDBytes)
	}
	if !providerIDPattern.MatchString(p.ProviderID) {
		return invalidf("provider_id must match %s", providerIDPattern)
	}
	if !p.Type.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownProviderType, p.Type)
	}
	if len(p.Version) == 0 || len(p.Version) > MaxVersionBytes || !versionPattern.MatchString(p.Version) {
		return invalidf("version must be semantic version text up to %d bytes", MaxVersionBytes)
	}
	if len(p.Namespace) > MaxNamespaceBytes {
		return invalidf("namespace exceeds %d bytes", MaxNamespaceBytes)
	}
	if err := crp.ValidateNamespace(p.Namespace); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPack, err)
	}
	if len(p.Source) > MaxSourceBytes {
		return invalidf("source exceeds %d bytes", MaxSourceBytes)
	}
	if err := crp.ValidateSource(p.Source); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPack, err)
	}
	if len(p.SourceRoot) > MaxSourceRootBytes {
		return invalidf("source_root exceeds %d bytes", MaxSourceRootBytes)
	}
	if err := crp.ValidateSourceRoot(p.SourceRoot); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPack, err)
	}
	if err := validateConfigSchema(p.ConfigSchema); err != nil {
		return err
	}
	if err := validateSecretFields(p.SecretFields, p.ConfigSchema); err != nil {
		return err
	}
	if err := validateEndpointTemplates(p.EndpointTemplates, p.ConfigSchema); err != nil {
		return err
	}
	if err := validateCapabilities(p.Capabilities); err != nil {
		return err
	}
	return validatePublication(p.Publication)
}

func validateConfigSchema(schema ConfigSchema) error {
	if schema.Type != "object" {
		return invalidf("config_schema.type must be %q", "object")
	}
	if len(schema.Properties) == 0 {
		return invalidf("config_schema.properties must not be empty")
	}
	if len(schema.Properties) > MaxConfigProperties {
		return invalidf("config_schema has %d properties; max %d", len(schema.Properties), MaxConfigProperties)
	}
	for name, property := range schema.Properties {
		if !fieldNamePattern.MatchString(name) {
			return invalidf("config property %q must match %s", name, fieldNamePattern)
		}
		switch property.Type {
		case "string", "boolean", "integer", "number":
		default:
			return invalidf("config property %q has unsupported type %q", name, property.Type)
		}
		if len(property.Description) > MaxDescriptionBytes {
			return invalidf("config property %q description exceeds %d bytes", name, MaxDescriptionBytes)
		}
		if property.Secret && property.Type != "string" {
			return invalidf("config property %q is secret but not a string", name)
		}
		if property.Secret && len(property.Enum) > 0 {
			return invalidf("config property %q is secret and must not declare an enum", name)
		}
		if len(property.Enum) > MaxEnumValues {
			return invalidf("config property %q has %d enum values; max %d", name, len(property.Enum), MaxEnumValues)
		}
		seen := make(map[string]struct{}, len(property.Enum))
		for _, value := range property.Enum {
			if value == "" || len(value) > MaxEnumValueBytes {
				return invalidf("config property %q enum values must be 1-%d bytes", name, MaxEnumValueBytes)
			}
			if _, duplicate := seen[value]; duplicate {
				return fmt.Errorf("%w: config property %q repeats enum value %q", ErrInvalidPack, name, value)
			}
			seen[value] = struct{}{}
		}
	}
	if len(schema.Required) > MaxRequiredFields {
		return invalidf("config_schema has %d required fields; max %d", len(schema.Required), MaxRequiredFields)
	}
	seenRequired := make(map[string]struct{}, len(schema.Required))
	for _, name := range schema.Required {
		if _, ok := schema.Properties[name]; !ok {
			return invalidf("required field %q is not declared in config_schema.properties", name)
		}
		if _, duplicate := seenRequired[name]; duplicate {
			return fmt.Errorf("%w: config_schema repeats required field %q", ErrInvalidPack, name)
		}
		seenRequired[name] = struct{}{}
	}
	return nil
}

func validateSecretFields(secretFields []string, schema ConfigSchema) error {
	if len(secretFields) > MaxSecretFields {
		return invalidf("secret_fields has %d entries; max %d", len(secretFields), MaxSecretFields)
	}
	listed := make(map[string]struct{}, len(secretFields))
	for _, name := range secretFields {
		if !fieldNamePattern.MatchString(name) {
			return fmt.Errorf("%w: secret field %q must match %s", ErrSecretConflict, name, fieldNamePattern)
		}
		if _, duplicate := listed[name]; duplicate {
			return fmt.Errorf("%w: secret field %q is listed more than once", ErrSecretConflict, name)
		}
		property, declared := schema.Properties[name]
		if !declared {
			return fmt.Errorf("%w: secret field %q is not declared in config_schema.properties", ErrSecretConflict, name)
		}
		if !property.Secret {
			return fmt.Errorf("%w: secret field %q overlaps a non-secret config property", ErrSecretConflict, name)
		}
		listed[name] = struct{}{}
	}
	for name, property := range schema.Properties {
		if property.Secret {
			if _, ok := listed[name]; !ok {
				return fmt.Errorf("%w: config property %q is secret but absent from secret_fields", ErrSecretConflict, name)
			}
		}
	}
	return nil
}

func validateEndpointTemplates(templates map[string]string, schema ConfigSchema) error {
	if len(templates) > MaxEndpointTemplates {
		return invalidf("endpoint_templates has %d entries; max %d", len(templates), MaxEndpointTemplates)
	}
	for name, raw := range templates {
		if len(name) == 0 || len(name) > MaxEndpointNameBytes || !endpointNamePatt.MatchString(name) {
			return invalidf("endpoint template name %q must match %s", name, endpointNamePatt)
		}
		if err := validateEndpointTemplate(raw, schema); err != nil {
			return fmt.Errorf("%w: endpoint template %q: %w", ErrUnsafeEndpoint, name, err)
		}
	}
	return nil
}

func validateEndpointTemplate(raw string, schema ConfigSchema) error {
	if len(raw) == 0 || len(raw) > MaxEndpointURLBytes {
		return fmt.Errorf("template must be 1-%d bytes", MaxEndpointURLBytes)
	}
	if !utf8.ValidString(raw) {
		return fmt.Errorf("template is not valid UTF-8")
	}
	authorityStart := strings.Index(raw, "://")
	if authorityStart < 0 {
		return fmt.Errorf("template must be an absolute HTTPS URL")
	}
	authority := raw[authorityStart+3:]
	if cut := strings.IndexAny(authority, "/?#"); cut >= 0 {
		authority = authority[:cut]
	}
	if strings.ContainsAny(authority, "{}") {
		return fmt.Errorf("placeholders are not allowed in the scheme or host")
	}

	substituted := placeholderPattern.ReplaceAllString(raw, "x")
	if strings.ContainsAny(substituted, "{}") {
		return fmt.Errorf("malformed placeholder")
	}
	for _, match := range placeholderPattern.FindAllStringSubmatch(raw, -1) {
		name := match[1]
		if _, ok := schema.Properties[name]; !ok {
			return fmt.Errorf("placeholder %q is not a declared config property", name)
		}
	}

	parsed, err := netguard.ValidateURL(substituted, endpointPolicy)
	if err != nil {
		return err
	}
	if err := validatePublicEndpointHost(parsed); err != nil {
		return err
	}
	return nil
}

func validatePublicEndpointHost(parsed *url.URL) error {
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if !netguard.IsPublicIP(ip) {
			return fmt.Errorf("host IP must be public")
		}
		return nil
	}
	if host == "localhost" || !strings.Contains(host, ".") {
		return fmt.Errorf("host must be a public DNS name")
	}
	for _, suffix := range rejectedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return fmt.Errorf("host %q is not public", host)
		}
	}
	return nil
}

func validateCapabilities(capabilities []Capability) error {
	if len(capabilities) == 0 {
		return invalidf("capabilities must declare at least one capability")
	}
	if len(capabilities) > MaxCapabilities {
		return invalidf("capabilities has %d entries; max %d", len(capabilities), MaxCapabilities)
	}
	seen := make(map[Capability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if len(capability) == 0 || len(capability) > MaxCapabilityBytes {
			return invalidf("capability must be 1-%d bytes", MaxCapabilityBytes)
		}
		if _, ok := allowedCapabilities[capability]; !ok {
			return invalidf("unsupported capability %q", capability)
		}
		if _, duplicate := seen[capability]; duplicate {
			return fmt.Errorf("%w: capability %q is repeated", ErrInvalidPack, capability)
		}
		seen[capability] = struct{}{}
	}
	return nil
}

func validatePublication(publication Publication) error {
	if publication.Status != PublicationStatusPlanned {
		return invalidf("publication.status must be %q", PublicationStatusPlanned)
	}
	if publication.Installable {
		return fmt.Errorf("%w: publication.installable must be false", ErrNotInstallable)
	}
	if publication.CRPBinding != CRPBindingDescriptorOnly {
		return fmt.Errorf("%w: publication.crp_binding must be %q", ErrNotInstallable, CRPBindingDescriptorOnly)
	}
	return nil
}
