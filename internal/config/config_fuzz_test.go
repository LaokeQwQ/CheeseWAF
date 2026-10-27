package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzConfigYAML covers the YAML decode + default + validation path without
// filesystem I/O. It must never panic on aliases, duplicate keys, large
// integers, or truncation.
func FuzzConfigYAML(f *testing.F) {
	for _, seed := range []string{
		"",
		"server:\n  listen: 127.0.0.1:8080\n",
		"a: &a [*a]\n",
		"server:\n  listen: 1\n  listen: 2\n",
		"server:\n  listen: 999999999999999999999999\n",
		"storage:\n  profile: production\n",
		"monitor:\n  notifiers:\n    - id: x\n      type: webhook\n      endpoint: http://127.0.0.1/\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		cfg := Default()
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return
		}
		applyDefaults(&cfg)
		// Validate is part of the security boundary; it may reject the config,
		// but it must not panic or retain an unsafe default.
		_ = Validate(&cfg)
	})
}
