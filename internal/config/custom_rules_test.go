package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCustomRulesYAMLMappingAndJSONArray(t *testing.T) {
	t.Parallel()
	yamlBody := []byte(`custom_rules:
  - id: block-admin-probe
    name: Admin path probe
    pattern: "(?i)/admin"
    location: uri
    action: block
    severity: medium
    enabled: true
    priority: 180
`)
	fromYAML, err := ParseCustomRules(yamlBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromYAML) != 1 || fromYAML[0].ID != "block-admin-probe" {
		t.Fatalf("yaml mapping: %+v", fromYAML)
	}

	jsonBody := []byte(`[
  {"id":"block-admin-probe","name":"Admin path probe","pattern":"(?i)/admin","location":"uri","action":"block","severity":"medium","enabled":true,"priority":180}
]`)
	fromJSON, err := ParseCustomRules(jsonBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromJSON) != 1 || fromJSON[0].Pattern != "(?i)/admin" {
		t.Fatalf("json array: %+v", fromJSON)
	}
}

func TestCustomRulesRoundTripPreservesDescription(t *testing.T) {
	t.Parallel()
	rules, err := ParseCustomRules([]byte(`{"custom_rules":[{"id":"described","name":"described","description":"blocks the known probe","pattern":"probe","location":"uri","action":"block","severity":"high","enabled":true,"priority":10}]}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCustomRules(rules, CustomRulesFormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"description": "blocks the known probe"`) {
		t.Fatalf("description was lost during parse/export: %s", encoded)
	}
}

func TestPrepareCustomRulesAcceptsQueryLocation(t *testing.T) {
	t.Parallel()
	prepared, err := PrepareCustomRules([]CustomRuleConfig{{
		ID: "query", Name: "query", Pattern: "debug=true", Location: "query", Action: "block", Severity: "medium", Enabled: true,
	}})
	if err != nil {
		t.Fatalf("query location should be valid: %v", err)
	}
	if len(prepared) != 1 || prepared[0].Location != "query" {
		t.Fatalf("unexpected prepared query rule: %+v", prepared)
	}
}

func TestPrepareCustomRulesRejectsInvalidBeforeReplace(t *testing.T) {
	t.Parallel()
	_, err := PrepareCustomRules([]CustomRuleConfig{
		{ID: "ok", Name: "ok", Pattern: "safe", Location: "uri", Action: "block", Severity: "low", Enabled: true},
		{ID: "bad", Name: "bad", Pattern: "(", Location: "uri", Action: "block", Severity: "low", Enabled: true},
	})
	if err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestParseCustomRulesRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	for _, body := range [][]byte{
		[]byte(`{"custom_rules":[{"id":"bad","name":"bad","locaton":"uri","pattern":"probe","action":"block","enabled":true}]}`),
		[]byte("custom_rules:\n  - id: bad\n    name: bad\n    locaton: uri\n    pattern: probe\n    action: block\n    enabled: true\n"),
	} {
		if _, err := ParseCustomRules(body); err == nil {
			t.Fatalf("unknown rule fields must be rejected: %s", body)
		}
	}
}

func TestPrepareCustomRulesRejectsDuplicateIDOrMatch(t *testing.T) {
	t.Parallel()
	_, err := PrepareCustomRules([]CustomRuleConfig{
		{ID: "dup", Name: "first", Pattern: "aaa", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 10},
		{ID: "dup", Name: "second", Pattern: "bbb", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 11},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate rule IDs must be rejected, got %v", err)
	}
}

func TestPrepareCustomRulesRejectsTooManyRules(t *testing.T) {
	t.Parallel()
	rules := make([]CustomRuleConfig, 257)
	for index := range rules {
		rules[index] = CustomRuleConfig{ID: fmt.Sprintf("r-%d", index), Name: "rule", Pattern: fmt.Sprintf("p-%d", index), Location: "uri", Action: "block", Enabled: true}
	}
	if _, err := PrepareCustomRules(rules); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("rule count limit must be enforced, got %v", err)
	}
}

func TestEncodeCustomRulesRoundTrip(t *testing.T) {
	t.Parallel()
	original := ExampleCustomRules()
	for _, format := range []string{"yaml", "json"} {
		body, err := EncodeCustomRules(original, format)
		if err != nil {
			t.Fatalf("%s encode: %v", format, err)
		}
		parsed, err := ParseCustomRules(body)
		if err != nil {
			t.Fatalf("%s parse: %v", format, err)
		}
		prepared, err := PrepareCustomRules(parsed)
		if err != nil {
			t.Fatalf("%s prepare: %v", format, err)
		}
		if len(prepared) != len(original) || prepared[0].ID != original[0].ID {
			t.Fatalf("%s round-trip: %+v", format, prepared)
		}
	}
}

func TestExampleCustomRulesFilesMatchEncoder(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"yaml", "json"} {
		want, err := ExampleCustomRulesDocument(format)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("..", "..", "configs", CustomRuleFilename("custom_rules.example", format))
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s example file drifted from encoder\nwant:\n%s\ngot:\n%s", format, want, got)
		}
	}
}
