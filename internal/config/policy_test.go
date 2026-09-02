package config

import "testing"

func TestBudgetExhaustedPolicyFromWebAttack(t *testing.T) {
	cases := map[string]string{
		ProtectionLevelOff:    BudgetPolicyOpen,
		ProtectionLevelLow:    BudgetPolicyOpen,
		ProtectionLevelSmart:  BudgetPolicyClosed,
		ProtectionLevelHigh:   BudgetPolicyClosed,
		ProtectionLevelStrict: BudgetPolicyClosed,
		"":                    BudgetPolicyClosed,
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

// TestBudgetExhaustedPolicyMonotonic guards against reintroducing a WAF bypass:
// a stricter protection level must never get a more permissive budget fail-mode.
// When `high` mapped to `observe` while `smart` mapped to `closed`, an attacker
// only had to exhaust the 100ms detection budget and the payload went through.
//
// Verified by mutation testing: reverting `high` to `observe` makes this fail.
func TestBudgetExhaustedPolicyMonotonic(t *testing.T) {
	rank := map[string]int{
		BudgetPolicyClosed:  2,
		BudgetPolicyObserve: 1,
		BudgetPolicyOpen:    0,
	}
	levels := []string{ProtectionLevelLow, ProtectionLevelSmart, ProtectionLevelHigh, ProtectionLevelStrict}
	for i := 1; i < len(levels); i++ {
		lower, higher := levels[i-1], levels[i]
		gotLower, gotHigher := BudgetExhaustedPolicyFromWebAttack(lower), BudgetExhaustedPolicyFromWebAttack(higher)
		if rank[gotHigher] < rank[gotLower] {
			t.Fatalf("protection level inversion: %q maps to %q but stricter %q maps to %q", lower, gotLower, higher, gotHigher)
		}
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
