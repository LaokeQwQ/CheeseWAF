package setup

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// URLFileName is the first-install browser URL written under the data directory.
	URLFileName = "setup.url"

	// SetupURLTTL bounds how long the out-of-band setup URL remains usable. The
	// setup token itself is still validated by the API and is revoked on setup
	// completion; this bound only protects an unattended URL file.
	SetupURLTTL = 10 * time.Minute

	setupURLMaxBytes = 16 << 10
)

var (
	// ErrURLNotFound reports that no setup URL is available. A consumed URL has
	// the same result, which prevents callers from distinguishing replay from
	// an absent file.
	ErrURLNotFound = errors.New("setup URL not found")
	// ErrURLExpired reports that the setup URL exceeded its short delivery TTL.
	ErrURLExpired = errors.New("setup URL expired")
)

// BrowserURL is the first-install page, with the token in the URL fragment.
func BrowserURL(scheme, adminListen, token string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(adminListen))
	if err != nil {
		return ""
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/setup#setup_token=%s", scheme, net.JoinHostPort(host, port), url.QueryEscape(token))
}

// WriteURL stores the first-install URL next to the data directory. It keeps
// the historical error-only signature; callers that need a log-safe receipt
// should use WriteURLWithReceipt.
func WriteURL(dataDir, page string) error {
	_, err := WriteURLWithReceipt(dataDir, page)
	return err
}

// WriteURLWithReceipt writes a short-lived setup URL atomically with mode
// 0600 and returns a random receipt that contains no setup secret. The file is
// an operator-readable envelope so the URL remains easy to copy while its
// expiry and receipt are explicit.
func WriteURLWithReceipt(dataDir, page string) (string, error) {
	page = strings.TrimSpace(page)
	if dataDir == "" || page == "" {
		return "", nil
	}
	if strings.ContainsAny(page, "\r\n") {
		return "", errors.New("setup URL must not contain newline characters")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", err
	}
	receipt, err := randomReceipt()
	if err != nil {
		return "", fmt.Errorf("generate setup URL receipt: %w", err)
	}
	expiresAt := time.Now().UTC().Add(SetupURLTTL)
	payload := []byte(fmt.Sprintf("url=%s\nreceipt=%s\nexpires_at=%s\n", page, receipt, expiresAt.Format(time.RFC3339Nano)))

	tmp, err := os.CreateTemp(dataDir, ".setup.url-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	removeTemp := true
	defer func() {
		_ = tmp.Close()
		if removeTemp {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := tmp.Write(payload); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, filepath.Join(dataDir, URLFileName)); err != nil {
		return "", err
	}
	removeTemp = false
	// Keep the secret-bearing delivery file short-lived even when an operator
	// never consumes it. The receipt guard prevents a stale timer from deleting
	// a newer setup URL written after a restart or retry.
	time.AfterFunc(SetupURLTTL, func() { expireURL(dataDir, receipt) })
	return receipt, nil
}

// ReadURLOnce atomically claims and consumes the setup URL file. It returns
// ErrURLExpired for stale files and removes them in either case, making
// retries and explicit replay fail closed.
func ReadURLOnce(dataDir string) (string, error) {
	if dataDir == "" {
		return "", ErrURLNotFound
	}
	path := filepath.Join(dataDir, URLFileName)
	claim, err := claimURL(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrURLNotFound
		}
		return "", err
	}
	defer os.Remove(claim)

	info, err := os.Lstat(claim)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrURLNotFound
		}
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("setup URL claim is not a regular file")
	}
	file, err := os.Open(claim)
	if err != nil {
		return "", err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, setupURLMaxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(raw) > setupURLMaxBytes {
		return "", errors.New("setup URL file is too large")
	}
	page, _, expiresAt, err := parseURLPayload(raw, info.ModTime())
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if !now.Before(expiresAt) || now.Sub(info.ModTime()) > SetupURLTTL {
		return "", ErrURLExpired
	}
	return page, nil
}

func expireURL(dataDir, receipt string) {
	if dataDir == "" || receipt == "" {
		return
	}
	path := filepath.Join(dataDir, URLFileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > setupURLMaxBytes {
		return
	}
	_, currentReceipt, _, err := parseURLPayload(raw, info.ModTime())
	if err != nil || currentReceipt != receipt {
		return
	}
	_ = os.Remove(path)
}

// RemoveURL deletes the first-install URL file after setup completes. It is
// idempotent so completion cleanup can be safely retried.
func RemoveURL(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	err := os.Remove(filepath.Join(dataDir, URLFileName))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".setup.url-") {
			continue
		}
		if err := os.Remove(filepath.Join(dataDir, entry.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func randomReceipt() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "setup-" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func claimURL(path string) (string, error) {
	claimFile, err := os.CreateTemp(filepath.Dir(path), ".setup.url.claim-*")
	if err != nil {
		return "", err
	}
	claim := claimFile.Name()
	if err := claimFile.Close(); err != nil {
		_ = os.Remove(claim)
		return "", err
	}
	if err := os.Remove(claim); err != nil {
		return "", err
	}
	if err := os.Rename(path, claim); err != nil {
		_ = os.Remove(claim)
		return "", err
	}
	return claim, nil
}

func parseURLPayload(raw []byte, modTime time.Time) (string, string, time.Time, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "", "", time.Time{}, ErrURLNotFound
	}
	lines := strings.Split(text, "\n")
	if !strings.HasPrefix(lines[0], "url=") {
		// Read URL files written by older versions as one-time legacy records.
		return lines[0], "", modTime.UTC().Add(SetupURLTTL), nil
	}
	values := make(map[string]string, 3)
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	page := strings.TrimSpace(values["url"])
	if page == "" {
		return "", "", time.Time{}, errors.New("setup URL file has no URL")
	}
	if strings.ContainsAny(page, "\r\n") || strings.TrimSpace(values["receipt"]) == "" {
		return "", "", time.Time{}, errors.New("setup URL file has invalid envelope")
	}
	expiresRaw := strings.TrimSpace(values["expires_at"])
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return "", "", time.Time{}, errors.New("setup URL file has invalid expiry")
	}
	return page, strings.TrimSpace(values["receipt"]), expiresAt.UTC(), nil
}
