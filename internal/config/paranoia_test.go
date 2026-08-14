package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEffectiveParanoiaLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int
		want int
	}{
		{0, 0},
		{-1, DefaultParanoiaLevel},
		{5, 5},
		{6, DefaultParanoiaLevel},
		{1, 1},
		{2, 2},
		{3, 3},
		{4, 4},
	}
	for _, tc := range cases {
		if got := EffectiveParanoiaLevel(tc.in); got != tc.want {
			t.Fatalf("EffectiveParanoiaLevel(%d)=%d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestWAFConfigYAMLOmitsParanoiaLevelAsDefault(t *testing.T) {
	var omitted WAFConfig
	if err := yaml.Unmarshal([]byte("enabled: true\nmode: block\n"), &omitted); err != nil {
		t.Fatal(err)
	}
	if omitted.ParanoiaLevel != DefaultParanoiaLevel {
		t.Fatalf("omitted paranoia_level: got %d want %d", omitted.ParanoiaLevel, DefaultParanoiaLevel)
	}
	var explicitZero WAFConfig
	if err := yaml.Unmarshal([]byte("enabled: true\nmode: block\nparanoia_level: 0\n"), &explicitZero); err != nil {
		t.Fatal(err)
	}
	if explicitZero.ParanoiaLevel != 0 {
		t.Fatalf("explicit 0 must stay record-only, got %d", explicitZero.ParanoiaLevel)
	}
	raw, err := yaml.Marshal(WAFConfig{Enabled: true, Mode: "block", ParanoiaLevel: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "paranoia_level: 0") {
		t.Fatalf("explicit 0 must be written out, got %s", raw)
	}
}
