package migration

import "testing"

// New snapshot tables carry JSONB columns that the old fixed list did not
// normalize; a migrated row would compare unequal and abort recovery.
func TestCanonicalProductionValueNormalizesAnyJSONColumn(t *testing.T) {
	cases := []struct {
		column string
		value  string
		want   string
	}{
		{"external_ids", `["CVE-2026-1",  "CVE-2026-2"]`, `["CVE-2026-1","CVE-2026-2"]`},
		{"products", `[ "php" ]`, `["php"]`},
		{"rule_json", `{"b":2, "a":1}`, `{"a":1,"b":2}`},
		{"provenance_json", `{"approved":true}`, `{"approved":true}`},
	}
	for _, tc := range cases {
		cell, err := canonicalProductionValue(tc.column, tc.value)
		if err != nil {
			t.Fatalf("%s: %v", tc.column, err)
		}
		if cell.Text != tc.want {
			t.Fatalf("%s = %q, want %q", tc.column, cell.Text, tc.want)
		}
	}

	// Plain text that is not JSON must survive unchanged.
	cell, err := canonicalProductionValue("title", "UNION SELECT 1,2,3")
	if err != nil {
		t.Fatalf("plain text: %v", err)
	}
	if cell.Text != "UNION SELECT 1,2,3" {
		t.Fatalf("plain text = %q", cell.Text)
	}
	// Strict JSON columns still reject malformed payloads.
	if _, err := canonicalProductionValue("domains", "["); err == nil {
		t.Fatal("domains must reject invalid JSON")
	}
}
