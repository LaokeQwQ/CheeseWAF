package setup

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

var (
	generatedTokenMu sync.Mutex
	generatedToken   string
)

// GenerateSetupToken creates a high-entropy one-time setup token on first call.
// Returns the same token on subsequent calls within the same process lifetime.
func GenerateSetupToken() (string, error) {
	generatedTokenMu.Lock()
	defer generatedTokenMu.Unlock()

	if generatedToken != "" {
		return generatedToken, nil
	}

	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	generatedToken = base64.RawURLEncoding.EncodeToString(buf)
	return generatedToken, nil
}

// GetSetupToken returns the generated token if one exists, empty string otherwise.
func GetSetupToken() string {
	generatedTokenMu.Lock()
	defer generatedTokenMu.Unlock()
	return generatedToken
}
