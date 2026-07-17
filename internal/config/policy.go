package config

const (
	ProtectionLevelOff    = "off"
	ProtectionLevelLow    = "low"
	ProtectionLevelSmart  = "smart"
	ProtectionLevelHigh   = "high"
	ProtectionLevelStrict = "strict"

	// Detection budget exhausted policies (linked to web_attack by default).
	BudgetPolicyAuto    = "auto"    // derive from web_attack level
	BudgetPolicyOpen    = "open"    // pass + metrics (availability first)
	BudgetPolicyObserve = "observe" // log (and optional challenge path) without hard block
	BudgetPolicyClosed  = "closed"  // challenge (preferred) / strict enforcement when budget runs out
)

func DefaultProtectionPolicy() ProtectionPolicyConfig {
	return ProtectionPolicyConfig{
		WebAttack:   ProtectionLevelSmart,
		APISecurity: ProtectionLevelSmart,
		BotCC:       ProtectionLevelSmart,
		ThreatIntel: ProtectionLevelSmart,
	}
}

func (p ProtectionPolicyConfig) WithDefaults(defaults ProtectionPolicyConfig) ProtectionPolicyConfig {
	if p.WebAttack == "" {
		p.WebAttack = defaults.WebAttack
	}
	if p.APISecurity == "" {
		p.APISecurity = defaults.APISecurity
	}
	if p.BotCC == "" {
		p.BotCC = defaults.BotCC
	}
	if p.ThreatIntel == "" {
		p.ThreatIntel = defaults.ThreatIntel
	}
	return p
}

func EffectiveProtectionPolicy(global, site ProtectionPolicyConfig) ProtectionPolicyConfig {
	return site.WithDefaults(global.WithDefaults(DefaultProtectionPolicy()))
}

func IsProtectionLevel(value string) bool {
	switch value {
	case "", ProtectionLevelOff, ProtectionLevelLow, ProtectionLevelSmart, ProtectionLevelHigh, ProtectionLevelStrict:
		return true
	default:
		return false
	}
}

func IsBudgetExhaustedPolicy(value string) bool {
	switch value {
	case "", BudgetPolicyAuto, BudgetPolicyOpen, BudgetPolicyObserve, BudgetPolicyClosed:
		return true
	default:
		return false
	}
}

// BudgetExhaustedPolicyFromWebAttack maps control-panel web_attack levels to
// detection-budget failure semantics. FP-first: even "closed" prefers challenge
// over silent hard-block of incomplete analysis.
//
//	off/low  → open     (pass + metrics)
//	smart    → observe  (log, do not block solely for timeout)
//	high     → observe  (same, proxy may escalate challenge on budget category)
//	strict   → closed   (challenge when analysis cannot finish)
func BudgetExhaustedPolicyFromWebAttack(level string) string {
	switch level {
	case ProtectionLevelOff, ProtectionLevelLow:
		return BudgetPolicyOpen
	case ProtectionLevelHigh:
		return BudgetPolicyObserve
	case ProtectionLevelStrict:
		return BudgetPolicyClosed
	default: // smart and unknown
		return BudgetPolicyObserve
	}
}

// ResolveBudgetExhaustedPolicy returns the effective budget policy.
// override "auto"/empty → derive from webAttackLevel; otherwise use override.
func ResolveBudgetExhaustedPolicy(override, webAttackLevel string) string {
	switch override {
	case BudgetPolicyOpen, BudgetPolicyObserve, BudgetPolicyClosed:
		return override
	default:
		return BudgetExhaustedPolicyFromWebAttack(webAttackLevel)
	}
}
