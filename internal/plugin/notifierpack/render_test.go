package notifierpack

import (
	"net/url"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestRenderURLSubstitutesConfigValue(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	template := pack.EndpointTemplates[0]
	rendered, err := renderURL(template, pack, config.NotifierConfig{To: "abc123"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "https://open.larksuite.com/open-apis/bot/v2/hook/abc123"; rendered != want {
		t.Fatalf("rendered = %q, want %q", rendered, want)
	}
}

func TestRenderURLOmitsOptionalMissingValue(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	template := pack.EndpointTemplates[0]
	template.URLTemplate = "https://open.larksuite.com/open-apis/bot/v2/hook/{to}{msg_type}"
	template.Variables = []string{"to", "msg_type"}
	pack.ConfigSchema.Fields = append(pack.ConfigSchema.Fields, Field{Name: "msg_type", Kind: "string"})
	if err := pack.Validate(); err != nil {
		t.Fatalf("validate pack: %v", err)
	}
	rendered, err := renderURL(template, pack, config.NotifierConfig{To: "abc"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "https://open.larksuite.com/open-apis/bot/v2/hook/abc"; rendered != want {
		t.Fatalf("rendered = %q, want %q", rendered, want)
	}
}

func TestRenderURLRequiresRequiredValue(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	_, err = renderURL(pack.EndpointTemplates[0], pack, config.NotifierConfig{})
	if err == nil || !strings.Contains(err.Error(), `required config value "to"`) {
		t.Fatalf("error = %v, want missing required value", err)
	}
}

func TestRenderTemplateRejectsSecretFieldInURL(t *testing.T) {
	document := strings.Replace(validPackJSON, "hook/{to}", "hook/{token_ref}", 1)
	document = strings.Replace(document, `"variables": ["to"]`, `"variables": ["token_ref"]`, 1)
	document = strings.Replace(document, `"fields": [
      { "name": "endpoint", "kind": "url", "required": false, "max_length": 512 },
      { "name": "to", "kind": "string", "required": true, "max_length": 256 }
    ]`, `"fields": []`, 1)
	pack, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	_, err = renderURL(pack.EndpointTemplates[0], pack, config.NotifierConfig{Token: "pack-token"})
	if err == nil || !strings.Contains(err.Error(), "headers only") {
		t.Fatalf("error = %v, want secret-in-URL rejection", err)
	}
	if strings.Contains(err.Error(), "pack-token") {
		t.Fatalf("error leaks the token: %v", err)
	}
}

func TestRenderTemplateRejectsUndeclaredVariable(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	template := EndpointTemplate{
		Name:        "notify",
		URLTemplate: "https://open.larksuite.com/hook/{hook_id}",
		Variables:   []string{"hook_id"},
	}
	_, err = renderTemplate(template, pack, config.NotifierConfig{})
	if err == nil || !strings.Contains(err.Error(), `undeclared variable "hook_id"`) {
		t.Fatalf("error = %v, want undeclared variable rejection", err)
	}
}

func TestRenderTemplateRejectsUnsafeValue(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	for _, value := range []string{"abc\nX-Injected: 1", "abc def", "abc\\def"} {
		_, err := renderTemplate(pack.EndpointTemplates[0], pack, config.NotifierConfig{To: value})
		if err == nil || !strings.Contains(err.Error(), "whitespace or control characters") {
			t.Fatalf("value %q error = %v, want unsafe value rejection", value, err)
		}
	}
}

func TestRenderTemplateEnforcesMaxLength(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	_, err = renderTemplate(pack.EndpointTemplates[0], pack, config.NotifierConfig{To: strings.Repeat("a", 257)})
	if err == nil || !strings.Contains(err.Error(), "max_length") {
		t.Fatalf("error = %v, want max_length enforcement", err)
	}
}

func TestConfigValueMapping(t *testing.T) {
	cfg := config.NotifierConfig{
		Endpoint:      "https://hooks.example.com/x",
		To:            "ops",
		MsgType:       "text",
		AtMobiles:     []string{"15500000001", "15500000002"},
		SMTPHost:      "smtp.example.com",
		SMTPPort:      587,
		SMTPUsername:  "waf",
		TLSMode:       "starttls",
		From:          "waf@example.com",
		SubjectPrefix: "[cheesewaf]",
		Token:         "pack-token",
		Headers:       map[string]string{"channel": "soc", "Authorization": "token"},
	}
	want := map[string]string{
		"endpoint":       "https://hooks.example.com/x",
		"to":             "ops",
		"msg_type":       "text",
		"at_mobiles":     "15500000001,15500000002",
		"smtp_host":      "smtp.example.com",
		"smtp_port":      "587",
		"smtp_username":  "waf",
		"tls_mode":       "starttls",
		"from":           "waf@example.com",
		"subject_prefix": "[cheesewaf]",
	}
	for name, expected := range want {
		value, ok := configValue(name, cfg)
		if !ok || value != expected {
			t.Fatalf("configValue(%q) = %q, %v, want %q", name, value, ok, expected)
		}
	}
	for _, name := range []string{"token", "channel", "authorization", "headers", "unknown"} {
		if value, ok := configValue(name, cfg); ok {
			t.Fatalf("configValue(%q) resolved %q; credentials and headers must stay out of URLs", name, value)
		}
	}

	empty := config.NotifierConfig{}
	for _, name := range []string{"at_mobiles", "smtp_port"} {
		if _, ok := configValue(name, empty); ok {
			t.Fatalf("configValue(%q) reported a value for an unset config", name)
		}
	}

	withMap := cfg
	withMap.Config = map[string]string{"hook_id": "abc123", "to": "shadowed"}
	if value, ok := configValue("hook_id", withMap); !ok || value != "abc123" {
		t.Fatalf("config map fallback = %q, %v, want abc123", value, ok)
	}
	// Dedicated notifier keys win over the free-form map so a pack field cannot
	// shadow the endpoint or the recipient.
	if value, ok := configValue("to", withMap); !ok || value != "ops" {
		t.Fatalf("configValue(\"to\") = %q, want the dedicated config value", value)
	}
}

func TestRenderURLUsesConfigMapForDeclaredField(t *testing.T) {
	document := strings.Replace(validPackJSON, `"name": "to"`, `"name": "hook_id"`, 1)
	document = strings.Replace(document, `hook/{to}`, `hook/{hook_id}`, 1)
	document = strings.Replace(document, `"variables": ["to"]`, `"variables": ["hook_id"]`, 1)
	pack, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	rendered, err := renderURL(pack.EndpointTemplates[0], pack, config.NotifierConfig{
		Config: map[string]string{"hook_id": "abc123"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if want := "https://open.larksuite.com/open-apis/bot/v2/hook/abc123"; rendered != want {
		t.Fatalf("rendered = %q, want %q", rendered, want)
	}
	if _, err := renderURL(pack.EndpointTemplates[0], pack, config.NotifierConfig{}); err == nil || !strings.Contains(err.Error(), `required config value "hook_id"`) {
		t.Fatalf("error = %v, want required value rejection", err)
	}
}

func TestRenderTemplateKeepsHeadersOutOfConfigFieldValues(t *testing.T) {
	document := strings.Replace(validPackJSON, `"name": "to"`, `"name": "hook_id"`, 1)
	document = strings.Replace(document, `hook/{to}`, `hook/{hook_id}`, 1)
	document = strings.Replace(document, `"variables": ["to"]`, `"variables": ["hook_id"]`, 1)
	pack, err := Parse([]byte(document))
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	_, err = renderTemplate(pack.EndpointTemplates[0], pack, config.NotifierConfig{
		Headers: map[string]string{"hook_id": "from-header"},
	})
	if err == nil || !strings.Contains(err.Error(), `required config value "hook_id"`) {
		t.Fatalf("error = %v, headers must not satisfy a config field", err)
	}
}

func TestCheckRenderedURLRejectsHostChange(t *testing.T) {
	template, err := url.Parse("https://open.larksuite.com/hook/{to}")
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	rendered, err := url.Parse("https://evil.example.com/hook/abc")
	if err != nil {
		t.Fatalf("parse rendered: %v", err)
	}
	err = checkRenderedURL(template, rendered)
	if err == nil || !strings.Contains(err.Error(), `differs from template host "open.larksuite.com"`) {
		t.Fatalf("error = %v, want host mismatch rejection", err)
	}
}

func TestCheckRenderedURLRejectsPortChange(t *testing.T) {
	template, err := url.Parse("https://open.larksuite.com/hook")
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	rendered, err := url.Parse("https://open.larksuite.com:8443/hook")
	if err != nil {
		t.Fatalf("parse rendered: %v", err)
	}
	if err := checkRenderedURL(template, rendered); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("error = %v, want port mismatch rejection", err)
	}
}

func TestCheckRenderedURLAcceptsCaseAndDefaultPort(t *testing.T) {
	template, err := url.Parse("https://API.Example.com/hook")
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	rendered, err := url.Parse("HTTPS://api.example.com:443/hook")
	if err != nil {
		t.Fatalf("parse rendered: %v", err)
	}
	if err := checkRenderedURL(template, rendered); err != nil {
		t.Fatalf("check rendered: %v", err)
	}
}

func TestCheckRenderedURLRejectsNonHTTPSAndUserInfo(t *testing.T) {
	template, err := url.Parse("https://api.example.com/hook")
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	for _, raw := range []string{"http://api.example.com/hook", "https://user:pass@api.example.com/hook", "https://api.example.com/hook#frag"} {
		rendered, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse rendered %q: %v", raw, err)
		}
		if err := checkRenderedURL(template, rendered); err == nil {
			t.Fatalf("rendered %q accepted", raw)
		}
	}
}

func TestEndpointForOnlyAppliesOverrideWithoutVariables(t *testing.T) {
	pack, err := Parse([]byte(validPackJSON))
	if err != nil {
		t.Fatalf("parse valid pack: %v", err)
	}
	rendered, err := pack.endpointFor(pack.EndpointTemplates[0], config.NotifierConfig{
		Endpoint: "https://ignored.example.com/hook",
		To:       "abc",
	})
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	if want := "https://open.larksuite.com/open-apis/bot/v2/hook/abc"; rendered != want {
		t.Fatalf("endpoint = %q, want %q", rendered, want)
	}
}

func TestValidateEndpointOverride(t *testing.T) {
	if _, err := validateEndpointOverride("https://hooks.example.com/x?a=1"); err != nil {
		t.Fatalf("https override rejected: %v", err)
	}
	for _, raw := range []string{"http://hooks.example.com/x", "https://user:pass@hooks.example.com/x", "https:///x"} {
		if _, err := validateEndpointOverride(raw); err == nil {
			t.Fatalf("override %q accepted", raw)
		}
	}
}
