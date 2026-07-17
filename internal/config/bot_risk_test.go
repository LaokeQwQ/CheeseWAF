package config

import "testing"

func TestBotRiskDefaultsAndValidation(t *testing.T) {
	cfg := Default()
	bot := cfg.Protection.Bot
	if bot.RiskLevel != 2 || bot.RiskLowThreshold != 35 || bot.RiskMediumThreshold != 55 || bot.RiskHighThreshold != 75 || bot.RiskBlockThreshold != 95 || bot.RiskConfidenceMin != 0.6 {
		t.Fatalf("unexpected bot risk defaults: %+v", bot)
	}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("defaults should validate: %v", err)
	}

	invalid := []func(*BotProtectionConfig){
		func(bot *BotProtectionConfig) { bot.RiskLevel = 6 },
		func(bot *BotProtectionConfig) { bot.RiskMediumThreshold = bot.RiskLowThreshold },
		func(bot *BotProtectionConfig) { bot.RiskBlockThreshold = 101 },
		func(bot *BotProtectionConfig) { bot.RiskConfidenceMin = 0.49 },
	}
	for i, mutate := range invalid {
		candidate := Default()
		mutate(&candidate.Protection.Bot)
		if err := Validate(&candidate); err == nil {
			t.Fatalf("case %d should fail validation", i)
		}
	}
}
