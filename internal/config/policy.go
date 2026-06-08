package config

const (
	ProtectionLevelOff    = "off"
	ProtectionLevelLow    = "low"
	ProtectionLevelSmart  = "smart"
	ProtectionLevelHigh   = "high"
	ProtectionLevelStrict = "strict"
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
