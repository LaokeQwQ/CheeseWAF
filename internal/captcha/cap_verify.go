package captcha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	maxCapSecretBytes    = 16 << 10
	maxCapTokenBytes     = 16 << 10
	maxCapResponseBytes  = 4 << 10
	maxCapSecretFileSize = 4 << 10
	maxCapTimeout        = 30 * time.Second
)

var (
	errCapInvalidEndpoint = errors.New("cap siteverify endpoint must be an absolute HTTPS URL (HTTP is limited to loopback)")
	errCapInvalidSecret   = errors.New("cap siteverify secret is empty or too large")
	errCapSecretFile      = errors.New("cap siteverify secret file is unreadable, empty, or too large")
	errCapInvalidTimeout  = errors.New("cap siteverify timeout must be positive")
	errCapInvalidToken    = errors.New("cap siteverify token is empty or too large")
	errCapRequest         = errors.New("cap siteverify request failed")
	errCapResponse        = errors.New("cap siteverify returned an invalid response")
)

// CapVerifier verifies a single-use token with a Cap Standalone siteverify endpoint.
type CapVerifier struct {
	endpoint string
	secret   string
	client   *http.Client
}

// NewCapVerifier creates a verifier for a Cap Standalone siteverify endpoint.
// Plain HTTP is accepted only for loopback endpoints, primarily for local setups
// and tests. Redirects are never followed.
func NewCapVerifier(endpoint, secret string, timeout time.Duration) (*CapVerifier, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || strings.Contains(endpoint, "#") || !validCapEndpoint(parsed) {
		return nil, errCapInvalidEndpoint
	}
	if strings.TrimSpace(secret) == "" || len(secret) > maxCapSecretBytes {
		return nil, errCapInvalidSecret
	}
	if timeout <= 0 {
		return nil, errCapInvalidTimeout
	}
	if timeout > maxCapTimeout {
		timeout = maxCapTimeout
	}

	return &CapVerifier{
		endpoint: parsed.String(),
		secret:   secret,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// NewCapVerifierFromFile loads a small secret file and creates a verifier.
// Surrounding whitespace is removed; file contents are never included in errors.
func NewCapVerifierFromFile(endpoint, secretFile string, timeout time.Duration) (*CapVerifier, error) {
	if strings.TrimSpace(secretFile) == "" {
		return nil, errCapSecretFile
	}
	file, err := os.Open(secretFile)
	if err != nil {
		return nil, errCapSecretFile
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > maxCapSecretFileSize {
		return nil, errCapSecretFile
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxCapSecretFileSize))
	if err != nil {
		return nil, errCapSecretFile
	}
	secret := strings.TrimSpace(string(contents))
	if secret == "" {
		return nil, errCapSecretFile
	}
	return NewCapVerifier(endpoint, secret, timeout)
}

func validCapEndpoint(endpoint *url.URL) bool {
	if endpoint == nil || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" {
		return false
	}
	if endpoint.Hostname() == "" || endpoint.Host == "" || strings.ContainsAny(endpoint.String(), "\r\n\t ") {
		return false
	}
	switch strings.ToLower(endpoint.Scheme) {
	case "https":
		return true
	case "http":
		host := strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), ".")
		if host == "localhost" {
			return true
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	default:
		return false
	}
}

// Verify sends the token to Cap and returns the site's success decision.
// Errors deliberately omit the configured endpoint, secret, and token.
func (v *CapVerifier) Verify(ctx context.Context, token string) (bool, error) {
	if v == nil || v.client == nil || ctx == nil {
		return false, errCapRequest
	}
	if strings.TrimSpace(token) == "" || len(token) > maxCapTokenBytes {
		return false, errCapInvalidToken
	}

	body, err := json.Marshal(struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
	}{Secret: v.secret, Response: token})
	if err != nil || len(body) > (maxCapSecretBytes+maxCapTokenBytes+128) {
		return false, errCapRequest
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, errCapRequest
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := v.client.Do(request)
	if err != nil {
		return false, errCapRequest
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return false, fmt.Errorf("%w: unexpected HTTP status", errCapResponse)
	}

	limited := io.LimitReader(response.Body, maxCapResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil || len(responseBody) > maxCapResponseBytes {
		return false, errCapResponse
	}
	var result struct {
		Success *bool `json:"success"`
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	if err := decoder.Decode(&result); err != nil || result.Success == nil {
		return false, errCapResponse
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, errCapResponse
	}
	return *result.Success, nil
}
