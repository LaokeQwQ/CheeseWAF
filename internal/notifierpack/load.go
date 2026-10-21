package notifierpack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const hashDomain = "cheesewaf.notifier-pack.v1\n"

var rejectedJSONKeys = map[string]error{
	"executable":     ErrExecutableContent,
	"executables":    ErrExecutableContent,
	"entrypoint":     ErrExecutableContent,
	"entrypoints":    ErrExecutableContent,
	"artifact":       ErrExecutableContent,
	"artifacts":      ErrExecutableContent,
	"binary":         ErrExecutableContent,
	"binaries":       ErrExecutableContent,
	"script":         ErrExecutableContent,
	"scripts":        ErrExecutableContent,
	"command":        ErrExecutableContent,
	"commands":       ErrExecutableContent,
	"process":        ErrExecutableContent,
	"install":        ErrExecutableContent,
	"installer":      ErrExecutableContent,
	"activation":     ErrExecutableContent,
	"activate":       ErrExecutableContent,
	"payload":        ErrExecutableContent,
	"wasm":           ErrExecutableContent,
	"egress":         ErrEgressTarget,
	"egress_targets": ErrEgressTarget,
	"egress_hosts":   ErrEgressTarget,
	"egress_policy":  ErrEgressTarget,
	"allowed_egress": ErrEgressTarget,
	"allow_egress":   ErrEgressTarget,
	"outbound_hosts": ErrEgressTarget,
}

// Load decodes, normalizes, and validates a provider pack.
func Load(data []byte) (*ProviderPack, error) {
	return LoadWithOptions(data, LoadOptions{})
}

// LoadWithOptions performs the same admission as Load and additionally
// cross-checks the pack's config schema against an optional expected schema
// keyed by provider type.
func LoadWithOptions(data []byte, opts LoadOptions) (*ProviderPack, error) {
	pack, err := decodeStrict(data)
	if err != nil {
		return nil, err
	}
	pack.normalize()
	if err := pack.Validate(); err != nil {
		return nil, err
	}
	if err := checkExpectedSchema(pack, opts); err != nil {
		return nil, err
	}
	return pack, nil
}

func decodeStrict(data []byte) (*ProviderPack, error) {
	if len(data) == 0 {
		return nil, invalidf("descriptor is empty")
	}
	if len(data) > MaxPackBytes {
		return nil, fmt.Errorf("%w: %d bytes; max %d", ErrPackTooLarge, len(data), MaxPackBytes)
	}
	if !utf8.Valid(data) {
		return nil, invalidf("descriptor is not valid UTF-8")
	}
	if err := scanJSON(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var pack ProviderPack
	if err := decoder.Decode(&pack); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	return &pack, nil
}

// scanJSON enforces document-level rules that encoding/json does not: a
// bounded nesting depth, no duplicate object members, and no keys that would
// smuggle executable content or egress policy past DisallowUnknownFields.
func scanJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return invalidf("descriptor nesting exceeds %d levels", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidPack, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return invalidf("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%w: %q", ErrDuplicateField, key)
			}
			seen[key] = struct{}{}
			if rejected, exists := rejectedJSONKeys[strings.ToLower(key)]; exists {
				return fmt.Errorf("%w: field %q is not permitted", rejected, key)
			}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPack, err)
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPack, err)
		}
		return nil
	default:
		return invalidf("unexpected JSON delimiter %q", delim)
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return invalidf("descriptor contains multiple JSON values")
		}
		return fmt.Errorf("%w: %v", ErrInvalidPack, err)
	}
	return nil
}

func (p *ProviderPack) normalize() {
	p.APIVersion = strings.TrimSpace(p.APIVersion)
	p.ProviderID = strings.TrimSpace(p.ProviderID)
	p.Type = ProviderType(strings.TrimSpace(string(p.Type)))
	p.Version = strings.TrimSpace(p.Version)
	p.Namespace = strings.TrimSpace(p.Namespace)
	p.Source = strings.TrimSpace(p.Source)
	p.SourceRoot = strings.TrimSpace(p.SourceRoot)

	if p.SecretFields == nil {
		p.SecretFields = []string{}
	}
	for i := range p.SecretFields {
		p.SecretFields[i] = strings.TrimSpace(p.SecretFields[i])
	}
	if p.Capabilities == nil {
		p.Capabilities = []Capability{}
	}
	for i := range p.Capabilities {
		p.Capabilities[i] = Capability(strings.TrimSpace(string(p.Capabilities[i])))
	}
	if p.EndpointTemplates != nil {
		for name, raw := range p.EndpointTemplates {
			p.EndpointTemplates[name] = strings.TrimSpace(raw)
		}
	}

	p.ConfigSchema = normalizeConfigSchema(p.ConfigSchema)
}

func normalizeConfigSchema(schema ConfigSchema) ConfigSchema {
	schema.Type = strings.TrimSpace(schema.Type)
	if schema.Properties != nil {
		properties := make(map[string]ConfigProperty, len(schema.Properties))
		for name, property := range schema.Properties {
			property.Description = strings.TrimSpace(property.Description)
			properties[name] = property
		}
		schema.Properties = properties
	}
	if schema.Required != nil {
		required := make([]string, len(schema.Required))
		for i, name := range schema.Required {
			required[i] = strings.TrimSpace(name)
		}
		schema.Required = required
	}
	return schema
}

func checkExpectedSchema(pack *ProviderPack, opts LoadOptions) error {
	if len(opts.ExpectedSchemas) == 0 {
		return nil
	}
	expected, ok := opts.ExpectedSchemas[pack.Type]
	if !ok {
		return nil
	}
	expected = normalizeConfigSchema(expected)
	if err := validateConfigSchema(expected); err != nil {
		return fmt.Errorf("%w: expected schema for %q: %v", ErrSchemaMismatch, pack.Type, err)
	}
	expectedJSON, err := canonicalJSON(expected)
	if err != nil {
		return fmt.Errorf("%w: expected schema for %q: %v", ErrSchemaMismatch, pack.Type, err)
	}
	actualJSON, err := canonicalJSON(pack.ConfigSchema)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSchemaMismatch, err)
	}
	if !bytes.Equal(expectedJSON, actualJSON) {
		return fmt.Errorf("%w: descriptor schema for %q does not match the expected schema", ErrSchemaMismatch, pack.Type)
	}
	return nil
}

// CanonicalJSON returns a deterministic JSON projection of the pack. Object
// keys are sorted and the input document's formatting is irrelevant.
func (p ProviderPack) CanonicalJSON() ([]byte, error) {
	return canonicalJSON(p)
}

// Hash returns the SHA-256 of the canonical JSON projection. Two equivalent
// descriptors produce the same hash regardless of input whitespace or member
// order; this binds catalog metadata, not the untrusted wire bytes.
func (p ProviderPack) Hash() (string, error) {
	canonical, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(hashDomain))
	_, _ = digest.Write(canonical)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, decoded); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if typed {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return err
		}
		buf.Write(encoded)
	case json.Number:
		buf.WriteString(typed.String())
	case []any:
		buf.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodedKey, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(encodedKey)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported canonical JSON type %T", value)
	}
	return nil
}
