package securitytest

import (
	"strings"
	"testing"
)

func TestLoadJSONLValidatesCorpusCases(t *testing.T) {
	raw := strings.Join([]string{
		`{"name":"attack","source_family":"unit","label":"attack","category":"sqli","method":"GET","target":"/?q=1%20or%201=1"}`,
		`  `,
		`{"name":"benign","source_family":"unit","label":"benign","method":"POST","target":"/docs","content_type":"application/json","body":"{\"text\":\"select docs\"}"}`,
	}, "\n")

	cases, err := LoadJSONL(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 {
		t.Fatalf("expected 2 cases, got %d", len(cases))
	}
	if cases[0].Name != "attack" || cases[1].Name != "benign" {
		t.Fatalf("unexpected cases: %+v", cases)
	}
}

func TestLoadJSONLRejectsInvalidCorpusCases(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{name: "bad label", raw: `{"name":"bad","label":"maybe","method":"GET","target":"/"}`},
		{name: "attack missing category", raw: `{"name":"bad","label":"attack","method":"GET","target":"/"}`},
		{name: "blank name", raw: `{"name":" ","label":"benign","method":"GET","target":"/"}`},
		{name: "missing method", raw: `{"name":"bad","label":"benign","target":"/"}`},
		{name: "missing target", raw: `{"name":"bad","label":"benign","method":"GET"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadJSONL(strings.NewReader(tc.raw)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
