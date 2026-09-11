package config

import (
	"strings"
	"testing"
)

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

func TestAIModelConfigRuntimeSeparatesDisplayAndInvocationModel(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "openai"
	cfg.AI.APIBase = "https://example.invalid/v1"
	cfg.AI.APIKey = "secret"
	cfg.AI.Model = "gateway/model"
	cfg.AI.Assistant = AIModelConfig{
		Provider:            "openai",
		APIBase:             "https://example.invalid/v1",
		APIKey:              "secret",
		Model:               "legacy-model",
		InvocationModelName: "provider-model",
		DisplayModelName:    "Customer visible model",
		ContextWindow:       131072,
		ReasoningEffort:     "high",
	}
	runtime := cfg.AI.AssistantRuntimeConfig()
	if runtime.Model != "provider-model" || runtime.InvocationModelName != "provider-model" || runtime.DisplayModelName != "Customer visible model" {
		t.Fatalf("unexpected runtime model identity: %+v", runtime)
	}
	if runtime.ContextWindow != 131072 || runtime.ReasoningEffort != "high" {
		t.Fatalf("runtime tuning not preserved: %+v", runtime)
	}
}

func TestValidateRejectsUnboundedAIModelSettings(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.APIBase = "https://example.invalid/v1"
	cfg.AI.APIKey = "secret"
	cfg.AI.Model = "provider-model"
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.ContextWindow = 2_000_001
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "context_window") {
		t.Fatal("expected context window bound error")
	}
	cfg.AI.ContextWindow = 128000
	cfg.AI.ReasoningEffort = "extreme"
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "reasoning_effort") {
		t.Fatal("expected reasoning effort enum error")
	}
}

func TestValidateRejectsEscapingAIProviderPathsAndUnknownCatalogEffort(t *testing.T) {
	cfg := Default()
	cfg.AI.Enabled = true
	cfg.AI.APIBase = "https://example.invalid/v1"
	cfg.AI.APIKey = "secret"
	cfg.AI.Model = "provider-model"
	cfg.AI.AllowPrivateAPIBase = true
	cfg.AI.ModelListPath = "https://attacker.invalid/models"
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "model_list_path") {
		t.Fatalf("expected provider path validation error, got %v", err)
	}

	cfg.AI.ModelListPath = "models"
	cfg.AI.ConfiguredCatalog = []AIModelCatalogEntry{{
		ID: "provider-model", ReasoningEfforts: []string{"high", "extreme"},
	}}
	if err := Validate(&cfg); err == nil || !strings.Contains(err.Error(), "reasoning_efforts") {
		t.Fatalf("expected catalog reasoning effort validation error, got %v", err)
	}
}
