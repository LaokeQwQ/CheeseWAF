package api

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/passkey"
)

const passkeySessionKeyDomain = "cheesewaf/passkey/session-key/v1\x00"

// NewPasskeyService builds the WebAuthn service from console configuration.
// It returns a nil service when passkeys are disabled, so the composition root
// can wire the result unconditionally. The auth secret is domain-separated
// rather than reused directly as the challenge-token HMAC key.
func NewPasskeyService(console config.PasskeyConfig, store passkey.Store, authSecret string) (*passkey.Service, error) {
	if !console.Enabled {
		return nil, nil
	}
	if store == nil {
		return nil, fmt.Errorf("passkey store is unavailable")
	}
	if strings.TrimSpace(authSecret) == "" {
		return nil, fmt.Errorf("passkey session key source is empty")
	}
	sum := sha256.Sum256([]byte(passkeySessionKeyDomain + authSecret))
	return passkey.NewService(passkey.Config{
		RPDisplayName:          console.RPDisplayName,
		RPID:                   console.RPID,
		RPOrigins:              append([]string(nil), console.RPOrigins...),
		AllowInsecureLocalhost: console.AllowInsecureLocalhost,
	}, passkey.Options{
		Store:      store,
		SessionKey: sum[:],
	})
}
