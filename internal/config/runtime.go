package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const BotSecretPlaceholder = "change-me-in-production"

func GenerateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func IsWeakBotSecret(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == BotSecretPlaceholder
}

func EnsureRuntimeSecrets(cfg *Config) (bool, error) {
	if cfg == nil {
		return false, nil
	}
	if !IsWeakBotSecret(cfg.Protection.Bot.Secret) {
		return false, nil
	}
	secret, err := GenerateSecret()
	if err != nil {
		return false, err
	}
	cfg.Protection.Bot.Secret = secret
	return true, nil
}
