package api

import (
	"crypto/rand"
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
// rather than reused directly as the challenge-token HMAC key. Each service
// receives a fresh key so rebuilding it invalidates previously issued tokens.
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
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate passkey session key: %w", err)
	}
	sum := sha256.Sum256(append([]byte(passkeySessionKeyDomain+authSecret), nonce[:]...))
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
