package setup

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	// SetupTokenFileName is the runtime token state used by the first-install
	// server and by `cheesewaf setup token`. It is deliberately separate from
	// setup.url: the URL is a short-lived delivery envelope, while this file is
	// the revocation source checked by the running API.
	SetupTokenFileName = "setup.token"

	setupTokenBytes = 256
)

// TokenSource is the small contract used by setup mutation handlers. A source
// may be backed by a file so a separate CLI process can rotate the token while
// the service is still running.
type TokenSource interface {
	Current() string
}

var (
	generatedTokenMu sync.Mutex
	generatedToken   string
)

// TokenStore persists the active first-install token in the runtime data
// directory. Current intentionally reads the file for every validation so a
// CLI rotation takes effect on the next request without restarting the
// service.
type TokenStore struct {
	dataDir string
	mu      sync.Mutex
}

// NewTokenStore creates a file-backed first-install token source.
func NewTokenStore(dataDir string) *TokenStore {
	return &TokenStore{dataDir: normalizeDataDir(dataDir)}
}

// TokenFilePath returns the runtime path used for the active setup token.
func TokenFilePath(dataDir string) string {
	return filepath.Join(normalizeDataDir(dataDir), SetupTokenFileName)
}

// Current returns the active token, or an empty string when the state is
// absent, malformed, or not a regular private file. Errors are intentionally
// fail-closed because this method is used on the HTTP authorization path.
func (s *TokenStore) Current() string {
	if s == nil || s.dataDir == "" {
		return ""
	}
	path := TokenFilePath(s.dataDir)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || validateSetupSecretFilePermissions(path, info) != nil {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > setupTokenBytes {
		return ""
	}
	token, err := normalizeToken(string(raw))
	if err != nil {
		return ""
	}
	return token
}

// Ensure keeps an existing token, otherwise persists the supplied token or a
// newly generated high-entropy value. This lets a restart preserve a token
// rotated by the CLI instead of allowing CHEESEWAF_SETUP_TOKEN to overwrite it.
func (s *TokenStore) Ensure(token string) (string, error) {
	if s == nil || s.dataDir == "" {
		return "", errors.New("setup token store data directory is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.Current(); current != "" {
		return current, nil
	}
	if strings.TrimSpace(token) == "" {
		var err error
		token, err = NewSetupToken()
		if err != nil {
			return "", err
		}
	}
	if err := s.write(token); err != nil {
		return "", err
	}
	return strings.TrimSpace(token), nil
}

// Rotate replaces the active token atomically. Readers either observe the
// previous complete value or the new complete value; there is no empty window.
func (s *TokenStore) Rotate() (string, error) {
	if s == nil || s.dataDir == "" {
		return "", errors.New("setup token store data directory is empty")
	}
	token, err := NewSetupToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.write(token); err != nil {
		return "", err
	}
	return token, nil
}

// Remove revokes the active token and removes its runtime state.
func (s *TokenStore) Remove() error {
	if s == nil || s.dataDir == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(TokenFilePath(s.dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *TokenStore) write(token string) error {
	token, err := normalizeToken(token)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dataDir, 0o750); err != nil {
		return fmt.Errorf("create setup token directory: %w", err)
	}
	tmp, err := os.CreateTemp(s.dataDir, ".setup.token-*")
	if err != nil {
		return fmt.Errorf("create setup token file: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := protectSetupSecretFile(tmpPath); err != nil {
		return fmt.Errorf("protect setup token file: %w", err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		return fmt.Errorf("write setup token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync setup token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close setup token file: %w", err)
	}
	if err := replaceSetupSecretFile(tmpPath, TokenFilePath(s.dataDir)); err != nil {
		return fmt.Errorf("publish setup token file: %w", err)
	}
	removeTemp = false
	return nil
}

func normalizeToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", errors.New("setup token is empty")
	}
	if len(token) > setupTokenBytes || strings.ContainsAny(token, "\r\n\t") {
		return "", errors.New("setup token has invalid length or whitespace")
	}
	for _, r := range token {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("setup token contains a control character")
		}
	}
	return token, nil
}

// NewSetupToken creates a fresh high-entropy setup token. Unlike
// GenerateSetupToken it never reuses a process-global value and is therefore
// suitable for explicit CLI rotation.
func NewSetupToken() (string, error) {
	buf := make([]byte, 32) // 256 bits
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateSetupToken creates a high-entropy one-time setup token on first call.
// Returns the same token on subsequent calls within the same process lifetime.
func GenerateSetupToken() (string, error) {
	generatedTokenMu.Lock()
	defer generatedTokenMu.Unlock()

	if generatedToken != "" {
		return generatedToken, nil
	}

	token, err := NewSetupToken()
	if err != nil {
		return "", err
	}
	generatedToken = token
	return generatedToken, nil
}

// GetSetupToken returns the generated token if one exists, empty string otherwise.
func GetSetupToken() string {
	generatedTokenMu.Lock()
	defer generatedTokenMu.Unlock()
	return generatedToken
}
