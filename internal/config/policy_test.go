package config

import (
	"strings"
	"testing"
)

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

// The response inspection fail-mode decides whether an uninspectable response
// (size limit, streaming media, unsupported encoding) is delivered. An omitted
// value resolves to the documented default, observe: the body is delivered and
// the coverage gap is logged. Withholding needs an explicit closed, and a typo
// must never silently pick a different exposure policy.
func TestNormalizeResponseFailMode(t *testing.T) {
	cases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "", want: ResponseFailModeObserve},
		{raw: "   ", want: ResponseFailModeObserve},
		{raw: ResponseFailModeOpen, want: ResponseFailModeOpen},
		{raw: " observe ", want: ResponseFailModeObserve},
		{raw: "CLOSED", want: ResponseFailModeClosed},
		{raw: "clossed", wantErr: true},
	}
	for _, tc := range cases {
		got, err := NormalizeResponseFailMode(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeResponseFailMode(%q) = %q, want error", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeResponseFailMode(%q) returned %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeResponseFailMode(%q) = %q, want %q", tc.raw, got, tc.want)
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

func TestValidateNotifierTypes(t *testing.T) {
	for _, typeName := range NotifierTypes() {
		notifier := NotifierConfig{
			ID:       typeName,
			Type:     typeName,
			Endpoint: "https://hooks.example.com/notify",
			Enabled:  true,
		}
		if typeName == "email" {
			notifier.Endpoint = "smtp://smtp.example.com:587"
			notifier.To = "ops@example.com"
			notifier.Headers = map[string]string{"from": "waf@example.com"}
		}

		cfg := Default()
		cfg.Monitor.Notifiers = []NotifierConfig{notifier}
		if err := Validate(&cfg); err != nil {
			t.Fatalf("notifier type %q rejected: %v", typeName, err)
		}
	}

	cfg := Default()
	cfg.Monitor.Notifiers = []NotifierConfig{{
		ID:       "pager",
		Type:     "pagerduty",
		Endpoint: "https://events.example.com/notify",
		Enabled:  true,
	}}
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), `notifier "pager" has invalid type "pagerduty"`) {
		t.Fatalf("unknown notifier type must be rejected, got %v", err)
	}
}
