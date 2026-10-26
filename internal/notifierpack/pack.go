// Package notifierpack defines the descriptor contract for external CheeseWAF
// notification provider packs.
//
// A provider pack is metadata only. It describes the configuration shape and
// endpoint templates a provider needs; it never contains executable content,
// artifacts, install instructions, or egress policy, and no descriptor can
// grant runtime permission. Delivery behavior remains the responsibility of
// the in-tree notifier manager and operator-supplied configuration.
package notifierpack

import "errors"

// APIVersion is the only descriptor schema accepted by this package.
const APIVersion = "crp.cheesewaf.io/notifier/v1"

// Limits bound every array, map, and string in a descriptor so a malformed or
// hostile pack cannot consume unbounded memory during admission.
const (
	MaxPackBytes           = 256 << 10
	MaxProviderIDBytes     = 128
	MaxVersionBytes        = 64
	MaxNamespaceBytes      = 128
	MaxSourceBytes         = 128
	MaxSourceRootBytes     = 128
	MaxConfigProperties    = 64
	MaxRequiredFields      = 64
	MaxSecretFields        = 32
	MaxEndpointTemplates   = 16
	MaxCapabilities        = 16
	MaxEnumValues          = 32
	MaxEnumValueBytes      = 128
	MaxDescriptionBytes    = 512
	MaxConfigPropertyBytes = 64
	MaxEndpointNameBytes   = 64
	MaxEndpointURLBytes    = 2048
	MaxCapabilityBytes     = 64
	maxJSONDepth           = 16
)

// Publication states are the only values the descriptor contract permits.
const (
	PublicationStatusPlanned = "planned"
	CRPBindingDescriptorOnly = "descriptor-only"
)

// Errors returned by Load and Validate. Callers use errors.Is to distinguish
// contract rejection from I/O or caller mistakes.
var (
	ErrInvalidPack         = errors.New("notifierpack: invalid provider pack")
	ErrPackTooLarge        = errors.New("notifierpack: provider pack exceeds size limit")
	ErrUnknownProviderType = errors.New("notifierpack: unsupported provider type")
	ErrNotInstallable      = errors.New("notifierpack: provider pack is not installable")
	ErrExecutableContent   = errors.New("notifierpack: provider pack contains executable or artifact content")
	ErrEgressTarget        = errors.New("notifierpack: provider pack declares an egress target")
	ErrUnsafeEndpoint      = errors.New("notifierpack: unsafe endpoint template")
	ErrSecretConflict      = errors.New("notifierpack: secret field conflict")
	ErrSchemaMismatch      = errors.New("notifierpack: config schema mismatch")
	ErrDuplicateField      = errors.New("notifierpack: duplicate JSON field")
)

// ProviderType is the notification transport a pack describes.
type ProviderType string

// Supported provider types. A descriptor cannot introduce new transports;
// unknown values are rejected at load time.
const (
	TypeWebhook  ProviderType = "webhook"
	TypeDingTalk ProviderType = "dingtalk"
	TypeFeishu   ProviderType = "feishu"
	TypeWeCom    ProviderType = "wecom"
	TypeTelegram ProviderType = "telegram"
	TypeEmail    ProviderType = "email"
)

// Valid reports whether the provider type is part of the descriptor contract.
func (t ProviderType) Valid() bool {
	switch t {
	case TypeWebhook, TypeDingTalk, TypeFeishu, TypeWeCom, TypeTelegram, TypeEmail:
		return true
	default:
		return false
	}
}

// String returns the wire value of the provider type.
func (t ProviderType) String() string { return string(t) }

// Capability is a declarative feature label such as send_text. It describes
// what a provider can render; it is not an authorization token.
type Capability string

// Declared, non-authorizing capability labels.
const (
	CapabilitySendText      Capability = "send_text"
	CapabilitySendMarkdown  Capability = "send_markdown"
	CapabilitySendHTML      Capability = "send_html"
	CapabilitySendCard      Capability = "send_card"
	CapabilityMention       Capability = "mention"
	CapabilityAttachment    Capability = "attachment"
	CapabilityRetry         Capability = "retry"
	CapabilityHMACSignature Capability = "hmac_signature"
)

// GrantsRuntimePermission always returns false. A capability label can never
// authorize delivery or any other runtime action.
func (c Capability) GrantsRuntimePermission() bool { return false }

// Publication records the descriptor-only publication state. Packs are
// catalog metadata: they are planned, not installable, and contain no CRP
// binding beyond the descriptor itself.
type Publication struct {
	Status      string `json:"status"`
	Installable bool   `json:"installable"`
	CRPBinding  string `json:"crp_binding"`
}

// ConfigProperty describes one operator-configurable field. Only scalar
// values are supported so a descriptor never embeds a nested executable or
// policy document.
type ConfigProperty struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Secret      bool     `json:"secret,omitempty"`
	Enum        []string `json:"enum,omitempty"`
}

// ConfigSchema is the strict, JSON-schema-shaped configuration contract for a
// provider. Additional properties are never accepted at runtime, so the
// descriptor lists every field explicitly.
type ConfigSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]ConfigProperty `json:"properties"`
	Required   []string                  `json:"required,omitempty"`
}

// ProviderPack is a validated notification provider descriptor. Values are
// normalized by Load: whitespace is trimmed, maps and slices are bounded, and
// endpoint templates are checked against the public HTTPS policy.
type ProviderPack struct {
	APIVersion        string            `json:"api_version"`
	ProviderID        string            `json:"provider_id"`
	Type              ProviderType      `json:"type"`
	Version           string            `json:"version"`
	Namespace         string            `json:"namespace"`
	Source            string            `json:"source"`
	SourceRoot        string            `json:"source_root"`
	ConfigSchema      ConfigSchema      `json:"config_schema"`
	SecretFields      []string          `json:"secret_fields"`
	EndpointTemplates map[string]string `json:"endpoint_templates,omitempty"`
	Capabilities      []Capability      `json:"capabilities"`
	Publication       Publication       `json:"publication"`
}

// GrantsRuntimePermission always returns false. Holding a loaded descriptor
// never authorizes sending, network access, or activation.
func (p ProviderPack) GrantsRuntimePermission() bool { return false }

// LoadOptions supplies admission context that cannot be derived from the
// descriptor alone.
type LoadOptions struct {
	// ExpectedSchemas optionally pins the configuration schema per provider
	// type. When a pack's type has an entry, its schema must match exactly
	// after normalization; otherwise Load fails with ErrSchemaMismatch.
	ExpectedSchemas map[ProviderType]ConfigSchema
}
