package notifierpack

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validPackMap() map[string]any {
	return map[string]any{
		"api_version": APIVersion,
		"provider_id": "dingtalk-primary",
		"type":        "dingtalk",
		"version":     "1.0.0",
		"namespace":   "official/notifier",
		"source":      "notifier/dingtalk",
		"source_root": "notifier-catalog",
		"config_schema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"webhook_url":     map[string]any{"type": "string"},
				"access_token":    map[string]any{"type": "string", "secret": true},
				"at_mobiles":      map[string]any{"type": "string"},
				"timeout_seconds": map[string]any{"type": "integer"},
			},
			"required": []string{"webhook_url", "access_token"},
		},
		"secret_fields": []string{"access_token"},
		"endpoint_templates": map[string]string{
			"send": "https://oapi.dingtalk.com/robot/send?access_token={access_token}",
		},
		"capabilities": []string{"send_text", "send_markdown", "mention"},
		"publication": map[string]any{
			"status":      "planned",
			"installable": false,
			"crp_binding": "descriptor-only",
		},
	}
}

func validPackJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(validPackMap())
	if err != nil {
		t.Fatalf("marshal valid pack: %v", err)
	}
	return data
}

func mutatePack(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	pack := validPackMap()
	mutate(pack)
	data, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal mutated pack: %v", err)
	}
	return data
}

func TestLoadValidPack(t *testing.T) {
	pack, err := Load(validPackJSON(t))
	if err != nil {
		t.Fatalf("Load valid pack: %v", err)
	}
	if pack.ProviderID != "dingtalk-primary" || pack.Type != TypeDingTalk {
		t.Fatalf("unexpected identity: %#v", pack)
	}
	if pack.GrantsRuntimePermission() {
		t.Fatal("loaded pack must not grant runtime permission")
	}
	for _, capability := range pack.Capabilities {
		if capability.GrantsRuntimePermission() {
			t.Fatalf("capability %q must not grant runtime permission", capability)
		}
	}
	hash, err := pack.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("hash length = %d, want 64", len(hash))
	}
	if err := pack.Validate(); err != nil {
		t.Fatalf("Validate loaded pack: %v", err)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	data := mutatePack(t, func(pack map[string]any) {
		pack["unexpected_field"] = true
	})
	_, err := Load(data)
	if !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("Load error = %v, want ErrInvalidPack", err)
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error %q does not mention unknown field", err)
	}
}

func TestLoadRejectsOversizedDescriptor(t *testing.T) {
	data := bytes.Repeat([]byte(" "), MaxPackBytes+1)
	_, err := Load(data)
	if !errors.Is(err, ErrPackTooLarge) {
		t.Fatalf("Load error = %v, want ErrPackTooLarge", err)
	}
}

func TestLoadRejectsInstallablePack(t *testing.T) {
	data := mutatePack(t, func(pack map[string]any) {
		publication := pack["publication"].(map[string]any)
		publication["installable"] = true
	})
	_, err := Load(data)
	if !errors.Is(err, ErrNotInstallable) {
		t.Fatalf("Load error = %v, want ErrNotInstallable", err)
	}
}

func TestLoadRejectsNonDescriptorPublication(t *testing.T) {
	data := mutatePack(t, func(pack map[string]any) {
		publication := pack["publication"].(map[string]any)
		publication["crp_binding"] = "full-package"
	})
	if _, err := Load(data); !errors.Is(err, ErrNotInstallable) {
		t.Fatalf("Load error = %v, want ErrNotInstallable", err)
	}
}

func TestLoadRejectsUnsupportedProviderType(t *testing.T) {
	data := mutatePack(t, func(pack map[string]any) {
		pack["type"] = "pagerduty"
	})
	_, err := Load(data)
	if !errors.Is(err, ErrUnknownProviderType) {
		t.Fatalf("Load error = %v, want ErrUnknownProviderType", err)
	}
}

func TestLoadRejectsUnsafeEndpointTemplates(t *testing.T) {
	tests := []struct {
		name     string
		template string
	}{
		{name: "plain http", template: "http://oapi.dingtalk.com/robot/send"},
		{name: "loopback IP", template: "https://127.0.0.1/robot/send"},
		{name: "private IP", template: "https://10.0.0.8/robot/send"},
		{name: "credentials", template: "https://user:pass@oapi.dingtalk.com/robot/send"},
		{name: "localhost", template: "https://localhost/robot/send"},
		{name: "internal suffix", template: "https://notify.internal/robot/send"},
		{name: "single label", template: "https://notify/robot/send"},
		{name: "placeholder host", template: "https://{access_token}.example.com/robot/send"},
		{name: "undeclared placeholder", template: "https://oapi.dingtalk.com/robot/send?access_token={missing_field}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := mutatePack(t, func(pack map[string]any) {
				pack["endpoint_templates"] = map[string]string{"send": test.template}
			})
			_, err := Load(data)
			if !errors.Is(err, ErrUnsafeEndpoint) {
				t.Fatalf("Load error = %v, want ErrUnsafeEndpoint", err)
			}
		})
	}
}

func TestLoadRejectsDuplicateJSONKey(t *testing.T) {
	data := []byte(`{"api_version":"crp.cheesewaf.io/notifier/v1","api_version":"crp.cheesewaf.io/notifier/v1"}`)
	_, err := Load(data)
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("Load error = %v, want ErrDuplicateField", err)
	}
}

func TestLoadRejectsSecretFieldConflicts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "secret list overlaps non-secret property",
			mutate: func(pack map[string]any) {
				pack["secret_fields"] = []string{"access_token", "at_mobiles"}
			},
		},
		{
			name: "secret property omitted from secret list",
			mutate: func(pack map[string]any) {
				pack["secret_fields"] = []string{}
			},
		},
		{
			name: "secret field not declared",
			mutate: func(pack map[string]any) {
				pack["secret_fields"] = []string{"access_token", "ghost_token"}
			},
		},
		{
			name: "duplicate secret field",
			mutate: func(pack map[string]any) {
				pack["secret_fields"] = []string{"access_token", "access_token"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(mutatePack(t, test.mutate))
			if !errors.Is(err, ErrSecretConflict) {
				t.Fatalf("Load error = %v, want ErrSecretConflict", err)
			}
		})
	}
}

func TestLoadRejectsExecutableContentAndEgressTargets(t *testing.T) {
	t.Run("artifact field", func(t *testing.T) {
		data := mutatePack(t, func(pack map[string]any) {
			pack["artifact"] = map[string]any{"name": "provider.bin"}
		})
		if _, err := Load(data); !errors.Is(err, ErrExecutableContent) {
			t.Fatalf("Load error = %v, want ErrExecutableContent", err)
		}
	})
	t.Run("script field", func(t *testing.T) {
		data := mutatePack(t, func(pack map[string]any) {
			pack["script"] = "setup.sh"
		})
		if _, err := Load(data); !errors.Is(err, ErrExecutableContent) {
			t.Fatalf("Load error = %v, want ErrExecutableContent", err)
		}
	})
	t.Run("nested command field", func(t *testing.T) {
		data := mutatePack(t, func(pack map[string]any) {
			pack["config_schema"].(map[string]any)["command"] = "run"
		})
		if _, err := Load(data); !errors.Is(err, ErrExecutableContent) {
			t.Fatalf("Load error = %v, want ErrExecutableContent", err)
		}
	})
	t.Run("egress targets", func(t *testing.T) {
		data := mutatePack(t, func(pack map[string]any) {
			pack["egress_targets"] = []string{"https://example.com"}
		})
		if _, err := Load(data); !errors.Is(err, ErrEgressTarget) {
			t.Fatalf("Load error = %v, want ErrEgressTarget", err)
		}
	})
}

func TestLoadRejectsUnknownCapability(t *testing.T) {
	data := mutatePack(t, func(pack map[string]any) {
		pack["capabilities"] = []string{"send_text", "install"}
	})
	if _, err := Load(data); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("Load error = %v, want ErrInvalidPack", err)
	}
}

func TestHashIsDeterministic(t *testing.T) {
	base, err := Load(validPackJSON(t))
	if err != nil {
		t.Fatalf("Load base: %v", err)
	}
	baseHash, err := base.Hash()
	if err != nil {
		t.Fatalf("Hash base: %v", err)
	}

	compact := mutatePack(t, func(map[string]any) {})
	indented := &bytes.Buffer{}
	if err := json.Indent(indented, compact, "", "    "); err != nil {
		t.Fatalf("indent pack: %v", err)
	}
	formatted, err := Load(indented.Bytes())
	if err != nil {
		t.Fatalf("Load formatted: %v", err)
	}
	formattedHash, err := formatted.Hash()
	if err != nil {
		t.Fatalf("Hash formatted: %v", err)
	}
	if formattedHash != baseHash {
		t.Fatalf("formatting changed hash: %s != %s", formattedHash, baseHash)
	}

	reordered, err := Load([]byte(reorderedValidPackJSON))
	if err != nil {
		t.Fatalf("Load reordered: %v", err)
	}
	reorderedHash, err := reordered.Hash()
	if err != nil {
		t.Fatalf("Hash reordered: %v", err)
	}
	if reorderedHash != baseHash {
		t.Fatalf("member order changed hash: %s != %s", reorderedHash, baseHash)
	}

	changed, err := Load(mutatePack(t, func(pack map[string]any) {
		pack["version"] = "1.0.1"
	}))
	if err != nil {
		t.Fatalf("Load changed: %v", err)
	}
	changedHash, err := changed.Hash()
	if err != nil {
		t.Fatalf("Hash changed: %v", err)
	}
	if changedHash == baseHash {
		t.Fatal("content change did not change hash")
	}
}

func TestCanonicalJSONSortsObjectKeys(t *testing.T) {
	pack, err := Load(validPackJSON(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	canonical, err := pack.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !json.Valid(canonical) {
		t.Fatal("canonical output is not valid JSON")
	}
	if bytes.Contains(canonical, []byte("\n")) {
		t.Fatal("canonical output must not contain formatting whitespace")
	}
	if !bytes.Contains(canonical, []byte(`"access_token":{"secret":true,"type":"string"}`)) {
		t.Fatalf("canonical output is not key-sorted: %s", canonical)
	}
}

func TestLoadWithExpectedSchema(t *testing.T) {
	data := validPackJSON(t)
	matching := ConfigSchema{
		Type: "object",
		Properties: map[string]ConfigProperty{
			"webhook_url":     {Type: "string"},
			"access_token":    {Type: "string", Secret: true},
			"at_mobiles":      {Type: "string"},
			"timeout_seconds": {Type: "integer"},
		},
		Required: []string{"webhook_url", "access_token"},
	}
	if _, err := LoadWithOptions(data, LoadOptions{ExpectedSchemas: map[ProviderType]ConfigSchema{TypeDingTalk: matching}}); err != nil {
		t.Fatalf("LoadWithOptions matching schema: %v", err)
	}

	mismatched := matching
	mismatched.Properties = map[string]ConfigProperty{
		"webhook_url": {Type: "string"},
	}
	if _, err := LoadWithOptions(data, LoadOptions{ExpectedSchemas: map[ProviderType]ConfigSchema{TypeDingTalk: mismatched}}); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("LoadWithOptions mismatched schema error = %v, want ErrSchemaMismatch", err)
	}

	if _, err := LoadWithOptions(data, LoadOptions{ExpectedSchemas: map[ProviderType]ConfigSchema{TypeEmail: mismatched}}); err != nil {
		t.Fatalf("unrelated expected schema should be ignored: %v", err)
	}
}

func TestLoadRequiresCoreFields(t *testing.T) {
	for _, field := range []string{"api_version", "provider_id", "version", "namespace", "source", "source_root", "config_schema", "capabilities", "publication"} {
		t.Run(field, func(t *testing.T) {
			data := mutatePack(t, func(pack map[string]any) {
				delete(pack, field)
			})
			if _, err := Load(data); !errors.Is(err, ErrInvalidPack) {
				t.Fatalf("Load without %s error = %v, want ErrInvalidPack", field, err)
			}
		})
	}
}

func TestLoadRejectsDuplicateRequiredField(t *testing.T) {
	data := mutatePack(t, func(pack map[string]any) {
		schema := pack["config_schema"].(map[string]any)
		schema["required"] = []string{"webhook_url", "webhook_url"}
	})
	if _, err := Load(data); !errors.Is(err, ErrInvalidPack) {
		t.Fatalf("Load error = %v, want ErrInvalidPack", err)
	}
}

const reorderedValidPackJSON = `{
	"publication": {"crp_binding":"descriptor-only","installable":false,"status":"planned"},
	"capabilities": ["send_text","send_markdown","mention"],
	"endpoint_templates": {"send": "https://oapi.dingtalk.com/robot/send?access_token={access_token}"},
	"secret_fields": ["access_token"],
	"config_schema": {
		"required": ["webhook_url","access_token"],
		"properties": {
			"timeout_seconds": {"type":"integer"},
			"at_mobiles": {"type":"string"},
			"access_token": {"secret":true,"type":"string"},
			"webhook_url": {"type":"string"}
		},
		"type": "object"
	},
	"source_root": "notifier-catalog",
	"source": "notifier/dingtalk",
	"namespace": "official/notifier",
	"version": "1.0.0",
	"type": "dingtalk",
	"provider_id": "dingtalk-primary",
	"api_version": "crp.cheesewaf.io/notifier/v1"
}`
