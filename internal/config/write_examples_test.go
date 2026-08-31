package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteExampleCustomRulesFiles(t *testing.T) {
	if os.Getenv("WRITE_CUSTOM_RULE_EXAMPLES") != "1" {
		t.Skip("set WRITE_CUSTOM_RULE_EXAMPLES=1 to regenerate example files")
	}
	root := filepath.Join("..", "..", "configs")
	for _, format := range []string{"yaml", "json"} {
		body, err := ExampleCustomRulesDocument(format)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, CustomRuleFilename("custom_rules.example", format))
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
