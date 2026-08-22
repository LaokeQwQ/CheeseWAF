package config

import "testing"

func TestBudgetExhaustedPolicyFromWebAttack(t *testing.T) {
	cases := map[string]string{
		ProtectionLevelOff:    BudgetPolicyOpen,
		ProtectionLevelLow:    BudgetPolicyOpen,
		ProtectionLevelSmart:  BudgetPolicyObserve,
		ProtectionLevelHigh:   BudgetPolicyObserve,
		ProtectionLevelStrict: BudgetPolicyClosed,
		"":                    BudgetPolicyObserve,
	}
	for level, want := range cases {
		if got := BudgetExhaustedPolicyFromWebAttack(level); got != want {
			t.Fatalf("level %q: got %q want %q", level, got, want)
		}
	}
}

func TestResolveBudgetExhaustedPolicy(t *testing.T) {
	if got := ResolveBudgetExhaustedPolicy(BudgetPolicyAuto, ProtectionLevelStrict); got != BudgetPolicyClosed {
		t.Fatalf("auto+strict: got %q", got)
	}
	if got := ResolveBudgetExhaustedPolicy(BudgetPolicyOpen, ProtectionLevelStrict); got != BudgetPolicyOpen {
		t.Fatalf("explicit open should override: got %q", got)
	}
	if got := ResolveBudgetExhaustedPolicy("", ProtectionLevelLow); got != BudgetPolicyOpen {
		t.Fatalf("empty+low: got %q", got)
	}
}

func TestResolveDecodeDepth(t *testing.T) {
	if got := ResolveDecodeDepth(0); got != DefaultDecodeDepth {
		t.Fatalf("omitted depth=%d, want %d", got, DefaultDecodeDepth)
	}
	if got := ResolveDecodeDepth(3); got != 3 {
		t.Fatalf("explicit depth=%d, want 3", got)
	}
	if got := ResolveDecodeDepth(MaxDecodeDepth + 1); got != MaxDecodeDepth {
		t.Fatalf("clamped depth=%d, want %d", got, MaxDecodeDepth)
	}
}
