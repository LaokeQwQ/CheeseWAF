package config

import "testing"

func TestAIConfigLegacyFieldsRemainAssistantFallback(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://example.invalid/v1"
	cfg.AI.APIKey = "legacy-key"
	cfg.AI.Model = "legacy-model"
	cfg.AI.MaxTokens = 4096

	assistant := cfg.AI.AssistantRuntimeConfig()
	if assistant.APIBase != "https://example.invalid/v1" || assistant.APIKey != "legacy-key" || assistant.Model != "legacy-model" || assistant.MaxTokens != 4096 {
		t.Fatalf("assistant runtime should inherit legacy fields, got %+v", assistant.RuntimeModelConfig())
	}
	reasoning := cfg.AI.ReasoningRuntimeConfig()
	if reasoning.APIBase != assistant.APIBase || reasoning.APIKey != assistant.APIKey || reasoning.Model != assistant.Model {
		t.Fatalf("reasoning runtime should inherit assistant when unset, got %+v", reasoning.RuntimeModelConfig())
	}
}

func TestAIConfigReasoningOverridesAssistantWhenSet(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://assistant.invalid/v1"
	cfg.AI.APIKey = "assistant-key"
	cfg.AI.Model = "assistant-model"
	cfg.AI.Reasoning = AIModelConfig{
		Provider:  "openai",
		APIBase:   "https://reasoning.invalid/v1",
		APIKey:    "reasoning-key",
		Model:     "reasoning-model",
		MaxTokens: 8192,
	}

	reasoning := cfg.AI.ReasoningRuntimeConfig()
	if reasoning.APIBase != "https://reasoning.invalid/v1" || reasoning.APIKey != "reasoning-key" || reasoning.Model != "reasoning-model" || reasoning.MaxTokens != 8192 {
		t.Fatalf("reasoning runtime should use explicit reasoning model, got %+v", reasoning.RuntimeModelConfig())
	}
}
