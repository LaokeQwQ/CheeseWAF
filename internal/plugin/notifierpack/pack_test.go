package notifierpack

import (
	"errors"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

// validPackJSON is a feishu-shaped pack: the URL carries the hook id supplied
// by operator config, while the token stays a reference resolved at send time.
const validPackJSON = `{
  "api_version": "crp.cheesewaf.io/notifier/v1",
  "provider_id": "lark.alert-bridge",
  "type": "lark",
  "version": "1.2.0",
  "namespace": "com.cheesewaf.official",
  "source": "cheesewaf-registry",
  "source_root": "packs/notifiers",
  "host_compatibility": { "min": "0.5.0", "max": "0.9.9" },
  "config_schema": {
    "dialect": "cheesewaf-notifier-config/v1",
    "fields": [
      { "name": "endpoint", "kind": "url", "required": false, "max_length": 512 },
      { "name": "to", "kind": "string", "required": true, "max_length": 256 }
    ]
  },
  "secret_fields": ["token_ref"],
  "endpoint_templates": [
    {
      "name": "notify",
      "url_template": "https://open.larksuite.com/open-apis/bot/v2/hook/{to}",
      "method": "POST",
      "egress_owner": "cheesewaf-core",
      "variables": ["to"]
    }
  ],
  "capabilities": ["alert_delivery", "test_delivery"]
}`

func TestParseAcceptsValidPack(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	if pack.ProviderID != "lark.alert-bridge" || pack.Type != "lark" || pack.Version != "1.2.0" {
		t.Fatalf("identity = %q/%q/%q", pack.ProviderID, pack.Type, pack.Version)
	}
	if len(pack.ConfigSchema.Fields) != 2 || pack.ConfigSchema.Fields[1].Name != "to" || !pack.ConfigSchema.Fields[1].Required {
		t.Fatalf("config fields = %#v", pack.ConfigSchema.Fields)
	}
	if len(pack.SecretFields) != 1 || pack.SecretFields[0] != "token_ref" {
		t.Fatalf("secret fields = %#v", pack.SecretFields)
	}
	if len(pack.EndpointTemplates) != 1 {
		t.Fatalf("templates = %#v", pack.EndpointTemplates)
	}
	template := pack.EndpointTemplates[0]
	if template.Name != "notify" || template.Method != "POST" || template.EgressOwner != "cheesewaf-core" {
		t.Fatalf("template = %#v", template)
	}
	if len(template.Variables) != 1 || template.Variables[0] != "to" {
		t.Fatalf("variables = %#v", template.Variables)
	}
	if len(pack.Capabilities) != 2 {
		t.Fatalf("capabilities = %#v", pack.Capabilities)
	}
}

func TestParseRejectsInvalidPacks(t *testing.T) {
	tests := []struct {
		name  string
		edits [][2]string
		want  string
		is    error
	}{
		{
			name:  "unknown field",
			edits: [][2]string{{`"capabilities": ["alert_delivery", "test_delivery"]`, `"capabilities": ["alert_delivery", "test_delivery"], "allowed_hosts": ["evil.example.com"]`}},
			want:  "unknown field",
		},
		{
			name:  "unknown host compatibility key",
			edits: [][2]string{{`"min": "0.5.0"`, `"minimum": "0.5.0"`}},
			want:  "unknown field",
		},
		{
			name:  "api version",
			edits: [][2]string{{`crp.cheesewaf.io/notifier/v1`, `crp.cheesewaf.io/notifier/v2`}},
			want:  "api_version",
		},
		{
			name:  "core provider type",
			edits: [][2]string{{`"type": "lark"`, `"type": "feishu"`}},
			want:  "core notifier",
			is:    ErrUnsupported,
		},
		{
			name:  "type not lowercase",
			edits: [][2]string{{`"type": "lark"`, `"type": "Lark"`}},
			want:  "lowercase",
		},
		{
			name:  "version not three components",
			edits: [][2]string{{`"version": "1.2.0"`, `"version": "1.2"`}},
			want:  "dotted numeric",
		},
		{
			name:  "version with leading zero",
			edits: [][2]string{{`"version": "1.2.0"`, `"version": "01.2.0"`}},
			want:  "dotted numeric",
		},
		{
			name:  "provider id starts with separator",
			edits: [][2]string{{`"provider_id": "lark.alert-bridge"`, `"provider_id": "-lark"`}},
			want:  "provider_id",
		},
		{
			name:  "empty namespace",
			edits: [][2]string{{`"namespace": "com.cheesewaf.official"`, `"namespace": ""`}},
			want:  "namespace",
		},
		{
			name:  "source root traversal",
			edits: [][2]string{{`"source_root": "packs/notifiers"`, `"source_root": "packs/../etc"`}},
			want:  "must not contain",
		},
		{
			name:  "http template",
			edits: [][2]string{{`"url_template": "https://open.larksuite.com`, `"url_template": "http://open.larksuite.com`}},
			want:  "https://",
		},
		{
			name:  "get method",
			edits: [][2]string{{`"method": "POST"`, `"method": "GET"`}},
			want:  "must be POST",
		},
		{
			name:  "pack owned egress",
			edits: [][2]string{{`"egress_owner": "cheesewaf-core"`, `"egress_owner": "cheesewaf-plugin"`}},
			want:  egressOwner,
		},
		{
			name:  "credentials in url",
			edits: [][2]string{{`https://open.larksuite.com`, `https://user:pass@open.larksuite.com`}},
			want:  "credentials",
		},
		{
			name:  "credentials in url are also high entropy",
			edits: [][2]string{{`https://open.larksuite.com`, `https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@open.larksuite.com`}},
			want:  "32+ character token",
		},
		{
			name:  "high entropy token in path",
			edits: [][2]string{{`hook/{to}`, `hook/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`}},
			want:  "32+ character token",
		},
		{
			name:  "undeclared variable",
			edits: [][2]string{{`hook/{to}`, `hook/{hook_id}`}},
			want:  "without declaring",
		},
		{
			name:  "variable missing from config schema",
			edits: [][2]string{{`hook/{to}`, `hook/{channel}`}, {`"variables": ["to"]`, `"variables": ["channel"]`}},
			want:  "not declared in config_schema.fields or secret_fields",
		},
		{
			name: "declared but unused variable",
			edits: [][2]string{
				{`{ "name": "to", "kind": "string", "required": true, "max_length": 256 }`, `{ "name": "to", "kind": "string", "required": true, "max_length": 256 },
      { "name": "msg_type", "kind": "string", "required": false, "max_length": 32 }`},
				{`"variables": ["to"]`, `"variables": ["to", "msg_type"]`},
			},
			want: "never uses",
		},
		{
			name:  "secret field without reference suffix",
			edits: [][2]string{{`"secret_fields": ["token_ref"]`, `"secret_fields": ["token"]`}},
			want:  "_ref",
		},
		{
			name:  "secret field looks like a credential",
			edits: [][2]string{{`"secret_fields": ["token_ref"]`, `"secret_fields": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_ref"]`}},
			want:  "credential value",
		},
		{
			name:  "missing notify template",
			edits: [][2]string{{`"name": "notify"`, `"name": "probe"`}},
			want:  notifyTemplateName,
		},
		{
			name:  "capability not allowed",
			edits: [][2]string{{`["alert_delivery", "test_delivery"]`, `["payload_exec"]`}},
			want:  "capability",
		},
		{
			name:  "no capabilities",
			edits: [][2]string{{`["alert_delivery", "test_delivery"]`, `[]`}},
			want:  "capabilities is required",
		},
		{
			name:  "field name not snake case",
			edits: [][2]string{{`"name": "to"`, `"name": "To"`}},
			want:  "config field name",
		},
		{
			name:  "duplicate field",
			edits: [][2]string{{`"name": "to"`, `"name": "endpoint"`}},
			want:  "duplicate config field",
		},
		{
			name:  "field length above cap",
			edits: [][2]string{{`"max_length": 256`, `"max_length": 4096`}},
			want:  "max_length",
		},
		{
			name:  "template without host",
			edits: [][2]string{{`"url_template": "https://open.larksuite.com/open-apis/bot/v2/hook/{to}"`, `"url_template": "https:///hook/{to}"`}},
			want:  "must name a host",
		},
		{
			name:  "template with fragment",
			edits: [][2]string{{`hook/{to}`, `hook/{to}#frag`}},
			want:  "fragment",
		},
		{
			name:  "template with whitespace",
			edits: [][2]string{{`hook/{to}`, `hook/{to} x`}},
			want:  "whitespace",
		},
		{
			name:  "template with unmatched brace",
			edits: [][2]string{{`hook/{to}`, `hook/{to}}`}},
			want:  "unmatched",
		},
		{
			name:  "template with unterminated placeholder",
			edits: [][2]string{{`hook/{to}`, `hook?to={to`}},
			want:  "unterminated",
		},
		{
			name:  "source root with backslash",
			edits: [][2]string{{`"source_root": "packs/notifiers"`, `"source_root": "packs\\notifiers"`}},
			want:  "backslashes",
		},
		{
			name:  "duplicate capability",
			edits: [][2]string{{`["alert_delivery", "test_delivery"]`, `["alert_delivery", "alert_delivery"]`}},
			want:  "declared twice",
		},
		{
			name:  "duplicate secret field",
			edits: [][2]string{{`"secret_fields": ["token_ref"]`, `"secret_fields": ["token_ref", "token_ref"]`}},
			want:  "duplicate secret field",
		},
		{
			name:  "empty document",
			edits: nil,
			want:  "empty",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := validPackJSON
			if test.edits == nil {
				document = ""
			}
			for _, edit := range test.edits {
				if !strings.Contains(document, edit[0]) {
					t.Fatalf("test edit %q does not apply to the sample document", edit[0])
				}
				document = strings.Replace(document, edit[0], edit[1], 1)
			}
			_, err := Parse([]byte(document))
			if err == nil {
				t.Fatalf("parse accepted a pack that must be rejected")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if test.is != nil && !errors.Is(err, test.is) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, test.is)
			}
			if !errors.Is(err, ErrInvalidPack) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("error = %v, want ErrInvalidPack or ErrUnsupported", err)
			}
		})
	}
}

func TestParseRejectsExecutableAndEgressKeys(t *testing.T) {
	tests := []struct {
		name string
		edit [2]string
		is   error
		want string
	}{
		{
			name: "executable at top level",
			edit: [2]string{`["alert_delivery", "test_delivery"]`, `["alert_delivery", "test_delivery"], "executable": "run.sh"`},
			is:   ErrExecutableContent,
			want: "executable",
		},
		{
			name: "artifact nested in a schema object",
			edit: [2]string{`"min": "0.5.0"`, `"min": "0.5.0", "artifact": {"url": "https://evil.example.com/p.bin"}`},
			is:   ErrExecutableContent,
			want: "artifact",
		},
		{
			name: "rejected key is case insensitive",
			edit: [2]string{`["alert_delivery", "test_delivery"]`, `["alert_delivery", "test_delivery"], "Command": "curl evil.example.com"`},
			is:   ErrExecutableContent,
			want: "Command",
		},
		{
			name: "egress target",
			edit: [2]string{`["alert_delivery", "test_delivery"]`, `["alert_delivery", "test_delivery"], "egress_hosts": ["evil.example.com"]`},
			is:   ErrEgressTarget,
			want: "egress_hosts",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := strings.Replace(validPackJSON, test.edit[0], test.edit[1], 1)
			_, err := Parse([]byte(document))
			if err == nil || !errors.Is(err, test.is) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, test.is)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want key %q in the message", err, test.want)
			}
		})
	}
}

func TestParseRejectsDuplicateJSONKeys(t *testing.T) {
	document := strings.Replace(validPackJSON,
		`"api_version": "crp.cheesewaf.io/notifier/v1"`,
		`"api_version": "crp.cheesewaf.io/notifier/v1", "api_version": "crp.cheesewaf.io/notifier/v1"`, 1)
	_, err := Parse([]byte(document))
	if err == nil || !strings.Contains(err.Error(), `duplicate field "api_version"`) {
		t.Fatalf("error = %v, want duplicate key rejection", err)
	}
}

func TestParseRejectsDeepNesting(t *testing.T) {
	document := strings.Replace(validPackJSON, `"packs/notifiers"`,
		strings.Repeat("[", 20)+`"packs/notifiers"`+strings.Repeat("]", 20), 1)
	_, err := Parse([]byte(document))
	if err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("error = %v, want nesting limit rejection", err)
	}
}

func TestParseRejectsMalformedDocuments(t *testing.T) {
	for _, document := range []string{"{", "[1,2]", "not json", "null"} {
		_, err := Parse([]byte(document))
		if err == nil || !errors.Is(err, ErrInvalidPack) {
			t.Fatalf("Parse(%q) error = %v, want ErrInvalidPack", document, err)
		}
	}
}

func TestParseRejectsTrailingJSON(t *testing.T) {
	_, err := Parse([]byte(validPackJSON + "\n{}"))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("error = %v, want trailing JSON rejection", err)
	}
}

func TestValidateRejectsOversizedCollections(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	fields := pack
	for len(fields.ConfigSchema.Fields) <= maxFields {
		fields.ConfigSchema.Fields = append(fields.ConfigSchema.Fields, Field{
			Name: "extra_" + string(rune('a'+len(fields.ConfigSchema.Fields))),
			Kind: "string",
		})
	}
	if err := fields.Validate(); err == nil || !strings.Contains(err.Error(), "limit is 24") {
		t.Fatalf("fields error = %v, want field limit", err)
	}

	templates := pack
	for len(templates.EndpointTemplates) <= maxEndpointTemplates {
		templates.EndpointTemplates = append(templates.EndpointTemplates, templates.EndpointTemplates[0])
	}
	if err := templates.Validate(); err == nil || !strings.Contains(err.Error(), "limit is 4") {
		t.Fatalf("templates error = %v, want template limit", err)
	}

	secrets := pack
	for len(secrets.SecretFields) <= maxSecretFields {
		secrets.SecretFields = append(secrets.SecretFields, "extra_ref")
	}
	if err := secrets.Validate(); err == nil || !strings.Contains(err.Error(), "limit is 16") {
		t.Fatalf("secrets error = %v, want secret limit", err)
	}
}

func TestValidateRejectsMalformedCollections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Pack)
		want   string
	}{
		{
			name:   "field kind not snake case",
			mutate: func(p *Pack) { p.ConfigSchema.Fields[0].Kind = "URL" },
			want:   "kind",
		},
		{
			name:   "negative field length",
			mutate: func(p *Pack) { p.ConfigSchema.Fields[0].MaxLength = -1 },
			want:   "max_length",
		},
		{
			name:   "duplicate template name",
			mutate: func(p *Pack) { p.EndpointTemplates = append(p.EndpointTemplates, p.EndpointTemplates[0]) },
			want:   "duplicate endpoint template",
		},
		{
			name:   "template name not snake case",
			mutate: func(p *Pack) { p.EndpointTemplates[0].Name = "Notify" },
			want:   "endpoint template name",
		},
		{
			name:   "duplicate template variable",
			mutate: func(p *Pack) { p.EndpointTemplates[0].Variables = []string{"to", "to"} },
			want:   "declares variable",
		},
		{
			name: "template longer than the cap",
			mutate: func(p *Pack) {
				p.EndpointTemplates[0].URLTemplate = "https://open.larksuite.com/" + strings.Repeat("a", 500)
			},
			want: "exceeds 512",
		},
		{
			name: "unparsable host bound",
			mutate: func(p *Pack) {
				p.HostCompatibility.Min = "zero"
			},
			want: "host_compatibility.min",
		},
		{
			name: "config field uses reserved ref suffix",
			mutate: func(p *Pack) {
				p.ConfigSchema.Fields = append(p.ConfigSchema.Fields, Field{Name: "to_ref", Kind: "string"})
			},
			want: "reserved for secret_fields",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Fresh parse per subtest: mutating a copied Pack would still share
			// the fields slice and leak the mutation into later cases.
			pack, err := Parse([]byte(validPackJSON))
			if err != nil {
				t.Fatalf("parse valid pack: %v", err)
			}
			test.mutate(&pack)
			err = pack.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestNotifyTemplateSelection(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	template, err := pack.notifyTemplate()
	if err != nil || template.Name != notifyTemplateName {
		t.Fatalf("notify template = %#v, %v", template, err)
	}

	single := Pack{ProviderID: "x", EndpointTemplates: []EndpointTemplate{{Name: "probe"}}}
	template, err = single.notifyTemplate()
	if err != nil || template.Name != "probe" {
		t.Fatalf("single template fallback = %#v, %v", template, err)
	}

	ambiguous := Pack{ProviderID: "x", EndpointTemplates: []EndpointTemplate{{Name: "a"}, {Name: "b"}}}
	if _, err := ambiguous.notifyTemplate(); err == nil || !strings.Contains(err.Error(), notifyTemplateName) {
		t.Fatalf("ambiguous template error = %v", err)
	}
}

func TestCheckHostBoundaries(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	tests := []struct {
		host         string
		wantErr      bool
		incompatible bool
	}{
		{host: "0.4.9", wantErr: true, incompatible: true},
		{host: "0.5.0"},
		{host: "0.7.3"},
		{host: "v0.9.9"},
		{host: "0.10.0", wantErr: true, incompatible: true},
		{host: "nightly", wantErr: true},
		{host: "", wantErr: true},
	}
	for _, test := range tests {
		err := pack.CheckHost(test.host)
		if test.wantErr != (err != nil) {
			t.Fatalf("CheckHost(%q) error = %v, wantErr %v", test.host, err, test.wantErr)
		}
		if test.incompatible != errors.Is(err, crp.ErrHostIncompatible) {
			t.Fatalf("CheckHost(%q) incompatible = %v, want %v", test.host, errors.Is(err, crp.ErrHostIncompatible), test.incompatible)
		}
		if err != nil && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("CheckHost(%q) error = %v, want ErrUnsupported", test.host, err)
		}
	}

	open := pack
	open.HostCompatibility = crp.HostCompatibility{}
	if err := open.CheckHost("99.0.0"); err != nil {
		t.Fatalf("open range rejected host: %v", err)
	}
	badBound := Pack{ProviderID: "lark", HostCompatibility: crp.HostCompatibility{Min: "0.5"}}
	if err := badBound.CheckHost("0.6.0"); err != nil {
		t.Fatalf("single component bounds are accepted by crp: %v", err)
	}
	typoBound := Pack{ProviderID: "lark", HostCompatibility: crp.HostCompatibility{Min: "0.x"}}
	if err := typoBound.CheckHost("0.6.0"); err == nil {
		t.Fatalf("unparsable bound must fail closed")
	}
}

// A pack that loads must always be usable from configuration: both layers use
// the same type-name rule, so a dotted or hyphenated name cannot slip in.
func TestPackTypeFollowsConfigurationNameRule(t *testing.T) {
	for _, name := range []string{"teams.webhook", "teams-webhook", "Teams", "1teams", "teams webhook"} {
		if config.ValidNotifierTypeName(name) {
			t.Fatalf("%q must be rejected by the configuration rule", name)
		}
		raw := strings.Replace(validPackJSON, `"type": "lark"`, `"type": "`+name+`"`, 1)
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("%q must be rejected by Parse", name)
		}
	}
	if !config.ValidNotifierTypeName("teams_webhook") {
		t.Fatal("a snake_case type must be accepted")
	}
}
