package bot

import (
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

// The configured flag decides whether a slider challenge requires a pointer
// track; the policy must not hardcode it.
func TestPolicyHonorsSliderTrackRequirement(t *testing.T) {
	for _, required := range []bool{true, false} {
		cfg := config.Default().Protection.Bot
		cfg.SliderCAPTCHATrackRequired = required
		policy := NewPolicy(cfg)
		if policy.sliderTrackRequired != required {
			t.Fatalf("sliderTrackRequired = %v, want %v", policy.sliderTrackRequired, required)
		}
	}
}
