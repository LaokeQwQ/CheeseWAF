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

func TestMergeCustomRulesRetainsUnmentionedRules(t *testing.T) {
	existing := []CustomRuleConfig{
		{ID: "keep", Name: "keep", Pattern: "keep-token", Location: "uri", Action: "block", Severity: "low", Enabled: true, Priority: 10},
		{ID: "replace", Name: "old", Pattern: "old-token", Location: "body", Action: "log", Severity: "low", Enabled: true, Priority: 20},
	}
	imported := []CustomRuleConfig{
		{ID: "replace", Name: "new", Pattern: "new-token", Location: "body", Action: "block", Severity: "high", Enabled: true, Priority: 30},
		{ID: "append", Name: "append", Pattern: "append-token", Location: "header", Action: "challenge", Severity: "medium", Enabled: true, Priority: 40},
	}
	merged, err := MergeCustomRules(existing, imported)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 || merged[0].ID != "keep" || merged[1].Name != "new" || merged[2].ID != "append" {
		t.Fatalf("unexpected merged rules: %+v", merged)
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

func TestCustomRuleFilenameSanitizesHeaderAndPathSyntax(t *testing.T) {
	got := CustomRuleFilename("../evil\r\nContent-Disposition: attachment", "json")
	if strings.ContainsAny(got, "/\\\r\n") || !strings.HasSuffix(got, ".json") || strings.Contains(got, "Content-Disposition: ") {
		t.Fatalf("unsafe custom rule filename: %q", got)
	}
}

func TestParseModSecurityPreservesBlockingActionAndStrictStringEquals(t *testing.T) {
	rules, err := ParseCustomRules([]byte(`SecRule REQUEST_URI "@streq /admin" "id:one,log,deny"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Action != "block" || rules[0].Location != "request_uri" {
		t.Fatalf("unexpected imported rule: %+v", rules)
	}
	if rules[0].Pattern != `\A/admin\z` {
		t.Fatalf("streq pattern = %q, want anchored literal", rules[0].Pattern)
	}
	if err := ValidateCustomRule(rules[0]); err != nil {
		t.Fatalf("anchored streq pattern must remain a valid native rule: %v", err)
	}
}

func TestParseModSecurityActionDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		actions string
		want    string
	}{
		{"id:one", "log"},
		{"id:one,msg:'observe',phase:2,severity:4,tag:'probe',capture,status:403", "log"},
		{"id:one,nolog", "log"},
		{"id:one,log", "log"},
		{"id:one,deny", "block"},
		{"id:one,drop", "block"},
		{"id:one,block", "block"},
		{"id:one,deny,log", "block"},
		{"id:one,log,deny", "block"},
		{"id:one,drop,log", "block"},
		{"id:one,log,drop", "block"},
		{"id:one,block,log", "block"},
		{"id:one,log,block", "block"},
	} {
		t.Run(tc.actions, func(t *testing.T) {
			rules, err := ParseCustomRules([]byte(fmt.Sprintf(`SecRule REQUEST_URI "@contains /admin" "%s"`, tc.actions)))
			if err != nil {
				t.Fatal(err)
			}
			merged, err := MergeCustomRules(nil, rules)
			if err != nil {
				t.Fatal(err)
			}
			if len(merged) != 1 || merged[0].Action != tc.want {
				t.Fatalf("imported action = %+v, want %q", merged, tc.want)
			}
		})
	}
}

func TestParseModSecurityKeepsDenyWhenLogAlsoPresent(t *testing.T) {
	rules, err := ParseCustomRules([]byte(`SecRule REQUEST_URI "@contains /admin" "id:one,deny,log"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Action != "block" {
		t.Fatalf("deny and log must retain blocking action: %+v", rules)
	}
}

func TestParseModSecurityLeavesMissingIDForMergeIdentity(t *testing.T) {
	rules, err := ParseCustomRules([]byte(`SecRule REQUEST_URI "@contains /admin" "deny"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "" {
		t.Fatalf("line-number IDs must not be treated as user identities: %+v", rules)
	}
}

func TestParseModSecurityARGSUsesCombinedArgumentLocation(t *testing.T) {
	rules, err := ParseCustomRules([]byte(`SecRule ARGS "@contains probe" "id:args,deny"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Location != "args" {
		t.Fatalf("ARGS must preserve query and form argument semantics, got %+v", rules)
	}
	if err := ValidateCustomRule(rules[0]); err != nil {
		t.Fatalf("imported ARGS rule should pass configuration validation: %v", err)
	}
}

func TestParseModSecurityMapsNumericSeverity(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"0", "critical"}, {"1", "critical"}, {"2", "critical"},
		{"3", "high"}, {"4", "medium"}, {"5", "low"}, {"6", "low"},
	}
	for _, tc := range tests {
		rules, err := ParseCustomRules([]byte(fmt.Sprintf(`SecRule REQUEST_URI "@contains probe" "id:test,severity:%s,deny"`, tc.value)))
		if err != nil {
			t.Fatalf("severity %s: %v", tc.value, err)
		}
		if got := rules[0].Severity; got != tc.want {
			t.Errorf("severity %s mapped to %q, want %q", tc.value, got, tc.want)
		}
	}
}

func TestMergeCustomRulesDoesNotUseDerivedIDsForReplacement(t *testing.T) {
	existing := []CustomRuleConfig{{Name: "same-name", Pattern: "old", Location: "uri", Action: "block", Enabled: true}}
	imported := []CustomRuleConfig{{ID: "same-name", Name: "new", Pattern: "new", Location: "body", Action: "block", Enabled: true}}
	merged, err := MergeCustomRules(existing, imported)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 {
		t.Fatalf("imported explicit ID must not replace unnamed rule, got %+v", merged)
	}
}

func TestParseModSecurityRejectsFieldSelectors(t *testing.T) {
	for _, variable := range []string{"ARGS:name", "REQUEST_HEADERS:Host", "REQUEST_COOKIES:session"} {
		_, err := ParseCustomRules([]byte(fmt.Sprintf(`SecRule %s "@contains probe" "id:test,deny"`, variable)))
		if err == nil || !strings.Contains(err.Error(), "unsupported variable") {
			t.Fatalf("%s should be rejected, got %v", variable, err)
		}
	}
}

func TestParseModSecurityRejectsHeaderAndCookieCollectionsAtomically(t *testing.T) {
	for _, variable := range []string{"REQUEST_HEADERS", "REQUEST_COOKIES"} {
		for _, operator := range []string{"rx", "contains", "streq"} {
			t.Run(variable+"/"+operator, func(t *testing.T) {
				body := fmt.Sprintf("SecRule REQUEST_URI \"@contains safe\" \"id:safe,deny\"\nSecRule %s \"@%s probe\" \"id:unsupported,deny\"", variable, operator)
				rules, err := ParseCustomRules([]byte(body))
				if err == nil || !strings.Contains(err.Error(), "line 2: unsupported variable") {
					t.Fatalf("collection semantics cannot use native combined text: rules=%+v err=%v", rules, err)
				}
				if rules != nil {
					t.Fatalf("unsupported collection must reject the complete import, got %+v", rules)
				}
			})
		}
	}
}

func TestParseCustomRulesPreservesNativeHeaderAndCookieLocations(t *testing.T) {
	for _, format := range []string{CustomRulesFormatJSON, CustomRulesFormatYAML} {
		t.Run(format, func(t *testing.T) {
			original := []CustomRuleConfig{
				{ID: "native-header", Pattern: `(?m)^X-Probe:probe$`, Location: "header", Action: "block", Enabled: true},
				{ID: "native-cookie", Pattern: `session=probe;`, Location: "cookie", Action: "block", Enabled: true},
			}
			body, err := EncodeCustomRules(original, format)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseCustomRules(body)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareCustomRules(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if len(prepared) != len(original) {
				t.Fatalf("native rules lost during import: %+v", prepared)
			}
			for index, rule := range original {
				if prepared[index].Location != rule.Location || prepared[index].Pattern != rule.Pattern {
					t.Fatalf("native combined-text semantics changed: got %+v want %+v", prepared[index], rule)
				}
			}
		})
	}
}

func TestMergeCustomRulesRefreshesReplacementIndexes(t *testing.T) {
	existing := []CustomRuleConfig{
		{ID: "first", Name: "first", Pattern: "one", Location: "uri", Action: "block", Enabled: true},
		{ID: "second", Name: "second", Pattern: "two", Location: "uri", Action: "block", Enabled: true},
	}
	imported := []CustomRuleConfig{
		{ID: "first", Name: "renamed", Pattern: "three", Location: "body", Action: "block", Enabled: true},
		{ID: "new", Name: "new", Pattern: "one", Location: "uri", Action: "log", Enabled: true},
	}
	merged, err := MergeCustomRules(existing, imported)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 3 || merged[0].Pattern != "three" || merged[2].ID != "new" {
		t.Fatalf("replacement index was stale: %+v", merged)
	}
}

func TestMergeCustomRulesPreservesIDForPatternReplacement(t *testing.T) {
	existing := []CustomRuleConfig{{
		ID: "stable-rule", Name: "old", Pattern: "probe", Location: "uri", Action: "block", Severity: "medium", Enabled: true,
	}}
	imported := []CustomRuleConfig{{
		Name: "renamed", Pattern: "probe", Location: "uri", Action: "log", Severity: "high", Enabled: true,
	}}
	merged, err := MergeCustomRules(existing, imported)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 1 || merged[0].ID != "stable-rule" || merged[0].Name != "renamed" || merged[0].Action != "log" {
		t.Fatalf("pattern replacement must preserve existing identity: %+v", merged)
	}
}

func TestMergeCustomRulesRemovesReplacedIDIndex(t *testing.T) {
	existing := []CustomRuleConfig{{ID: "old", Pattern: "probe", Enabled: true}}
	imported := []CustomRuleConfig{
		{ID: "new", Pattern: "probe", Action: "log", Enabled: true},
		{ID: "old", Pattern: "other", Enabled: true},
	}
	merged, err := MergeCustomRules(existing, imported)
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 || merged[0].ID != "new" || merged[0].Pattern != "probe" || merged[1].ID != "old" || merged[1].Pattern != "other" {
		t.Fatalf("replaced ID must no longer target the old index: %+v", merged)
	}
}

func TestMergeCustomRulesChecksFinalCountAfterReplacement(t *testing.T) {
	existing := make([]CustomRuleConfig, maxCustomRulesCount)
	for index := range existing {
		existing[index] = CustomRuleConfig{ID: fmt.Sprintf("r-%d", index), Pattern: fmt.Sprintf("p-%d", index), Enabled: true}
	}
	merged, err := MergeCustomRules(existing, []CustomRuleConfig{{Pattern: "p-0", Action: "log", Enabled: true}})
	if err != nil || len(merged) != maxCustomRulesCount || merged[0].ID != "r-0" || merged[0].Action != "log" {
		t.Fatalf("replacement at count limit must succeed: rules=%d err=%v", len(merged), err)
	}
	merged, err = MergeCustomRules(existing, []CustomRuleConfig{{Pattern: "new", Enabled: true}})
	if err == nil || !strings.Contains(err.Error(), "too many") || merged != nil {
		t.Fatalf("append beyond count limit must return no rules: rules=%d err=%v", len(merged), err)
	}
	if existing[0].Action != "" {
		t.Fatal("merge must not mutate its input")
	}
}

func TestPrepareCustomRulesReplacementAssignsIDsAndAcceptsEmptySet(t *testing.T) {
	rules, err := PrepareCustomRules([]CustomRuleConfig{
		{ID: "same-name", Pattern: "old", Enabled: true},
		{Name: "Same Name", Pattern: "new", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[1].ID != "same-name-2" {
		t.Fatalf("complete replacement must generate unique IDs: %+v", rules)
	}
	for _, input := range [][]CustomRuleConfig{nil, {}} {
		rules, err := PrepareCustomRules(input)
		if err != nil || len(rules) != 0 {
			t.Fatalf("empty replacement must clear the rule set: %+v, %v", rules, err)
		}
	}
}
