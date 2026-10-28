package cli

import (
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/intel"
)

func TestIntelRolloutPolicyUsesConfiguredShadowWindow(t *testing.T) {
	cfg := config.Default().Intel
	cfg.ShadowWindow = 72 * time.Hour
	if got := intelRolloutPolicy(cfg).MinShadowDuration; got != 72*time.Hour {
		t.Fatalf("shadow window = %s", got)
	}
	cfg.ShadowWindow = 0
	if got := intelRolloutPolicy(cfg).MinShadowDuration; got == 0 {
		t.Fatal("zero window must fall back to the impact default")
	}
}

func TestIntelSourceTrustPolicyAllowsSingleCommunitySource(t *testing.T) {
	cfg := config.Default().Intel
	cfg.AllowCommunitySingleSource = false
	if got := intelSourceTrustPolicy(cfg).RequiredCorroboration; got != intel.DefaultRequiredCorroboration {
		t.Fatalf("corroboration = %d, want the default", got)
	}
	cfg.AllowCommunitySingleSource = true
	if got := intelSourceTrustPolicy(cfg).RequiredCorroboration; got != 1 {
		t.Fatalf("corroboration = %d, want 1", got)
	}
}
