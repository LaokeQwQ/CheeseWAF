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
