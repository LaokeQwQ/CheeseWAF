package config

import (
	"strings"
	"testing"
)

func TestDefaultBotExemptPathPrefixesExcludeAPI(t *testing.T) {
	t.Parallel()
	cfg := Default()
	prefixes := cfg.Protection.Bot.ExemptPathPrefixes
	if len(prefixes) != 1 || prefixes[0] != "/health" {
		t.Fatalf("default exempt path prefixes = %v, want [/health] only", prefixes)
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(prefix, "/api") {
			t.Fatalf("default must not blanket-exempt /api/, got %v", prefixes)
		}
	}
}
