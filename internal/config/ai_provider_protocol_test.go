package config

import "testing"

func TestAIModelValidatorAcceptsExplicitOpenAIProtocolAliases(t *testing.T) {
	for _, provider := range []string{"openai-responses", "openai_response", "openai-chat", "openai_chat_completions"} {
		t.Run(provider, func(t *testing.T) {
			err := validateAIModelConfig("ai", AIModelConfig{
				Provider:            provider,
				APIBase:             "https://provider.example/v1",
				Model:               "model",
				AllowPrivateAPIBase: true,
			}, true)
			if err != nil {
				t.Fatalf("validate provider alias %q: %v", provider, err)
			}
		})
	}
}
