// Package passkey implements WebAuthn passkey primitives for CheeseWAF
// administrator accounts. It owns ceremony orchestration, signed challenge
// sessions, credential persistence contracts, and one-time recovery codes; HTTP
// routing and presentation are intentionally outside this package.
package passkey

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

const (
	// DefaultTimeout is the ceremony timeout advertised to clients.
	DefaultTimeout = 60 * time.Second
	// DefaultChallengeTTL is the lifetime of a signed challenge session token.
	DefaultChallengeTTL = 5 * time.Minute
	// MaxTimeout bounds the ceremony timeout accepted from configuration.
	MaxTimeout = 5 * time.Minute
	// MaxChallengeTTL bounds signed challenge session lifetime.
	MaxChallengeTTL = 10 * time.Minute

	maxRPDisplayNameLen = 128
	maxRPOrigins        = 10
)

// Config is the Relying Party policy. The zero UserVerification, Timeout, and
// ChallengeTTL values are replaced by secure defaults.
//
// AllowInsecureLocalhost is a test/development escape hatch: when true,
// http://localhost, http://127.0.0.1, and http://[::1] origins are accepted.
// It never permits plain HTTP for any other host.
type Config struct {
	RPDisplayName          string
	RPID                   string
	RPOrigins              []string
	UserVerification       protocol.UserVerificationRequirement
	Timeout                time.Duration
	ChallengeTTL           time.Duration
	AllowInsecureLocalhost bool
}

// Validate reports whether the configuration is usable. It does not mutate the
// receiver.
func (c Config) Validate() error {
	_, err := c.normalized()
	return err
}

// normalized returns a copy with defaults applied and every value validated.
func (c Config) normalized() (Config, error) {
	if c.RPID == "" || strings.TrimSpace(c.RPID) != c.RPID {
		return c, fmt.Errorf("%w: RPID must be a non-empty domain without surrounding spaces", ErrInvalidConfig)
	}

	if err := protocol.ValidateRPID(c.RPID); err != nil {
		return c, fmt.Errorf("%w: RPID %q is invalid: %v", ErrInvalidConfig, c.RPID, err)
	}

	if c.RPDisplayName == "" || strings.TrimSpace(c.RPDisplayName) == "" {
		return c, fmt.Errorf("%w: RPDisplayName is required", ErrInvalidConfig)
	}

	if len(c.RPDisplayName) > maxRPDisplayNameLen {
		return c, fmt.Errorf("%w: RPDisplayName exceeds %d bytes", ErrInvalidConfig, maxRPDisplayNameLen)
	}

	if len(c.RPOrigins) == 0 {
		return c, fmt.Errorf("%w: at least one RPOrigin is required", ErrInvalidConfig)
	}

	if len(c.RPOrigins) > maxRPOrigins {
		return c, fmt.Errorf("%w: at most %d RPOrigins are supported", ErrInvalidConfig, maxRPOrigins)
	}

	seen := make(map[string]struct{}, len(c.RPOrigins))
	origins := make([]string, 0, len(c.RPOrigins))

	for _, origin := range c.RPOrigins {
		if err := validateOrigin(origin, c.AllowInsecureLocalhost); err != nil {
			return c, err
		}

		host, err := originHost(origin)
		if err != nil {
			return c, err
		}

		if !originMatchesRPID(host, c.RPID, c.AllowInsecureLocalhost) {
			return c, fmt.Errorf("%w: origin %q does not belong to RPID %q", ErrInvalidConfig, origin, c.RPID)
		}

		key := strings.ToLower(origin)
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		origins = append(origins, origin)
	}

	c.RPOrigins = origins

	switch c.UserVerification {
	case "":
		c.UserVerification = protocol.VerificationRequired
	case protocol.VerificationRequired, protocol.VerificationPreferred:
		// Explicitly configured, accepted.
	case protocol.VerificationDiscouraged:
		return c, fmt.Errorf("%w: user verification must not be discouraged", ErrInvalidConfig)
	default:
		return c, fmt.Errorf("%w: unknown user verification requirement %q", ErrInvalidConfig, c.UserVerification)
	}

	if c.Timeout < 0 || c.Timeout > MaxTimeout {
		return c, fmt.Errorf("%w: Timeout must be between 0 and %s", ErrInvalidConfig, MaxTimeout)
	}

	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}

	if c.ChallengeTTL < 0 || c.ChallengeTTL > MaxChallengeTTL {
		return c, fmt.Errorf("%w: ChallengeTTL must be between 0 and %s", ErrInvalidConfig, MaxChallengeTTL)
	}

	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = DefaultChallengeTTL
	}

	return c, nil
}

func validateOrigin(origin string, allowInsecureLocalhost bool) error {
	if origin == "" || strings.TrimSpace(origin) != origin {
		return fmt.Errorf("%w: origin is empty or contains surrounding spaces", ErrInvalidConfig)
	}

	u, err := url.Parse(origin)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: origin %q is not an absolute URL", ErrInvalidConfig, origin)
	}

	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%w: origin %q must not contain credentials, a path, a query, or a fragment", ErrInvalidConfig, origin)
	}

	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecureLocalhost && isLoopbackHost(u.Hostname()) {
			return nil
		}

		return fmt.Errorf("%w: origin %q must use https", ErrInvalidConfig, origin)
	default:
		return fmt.Errorf("%w: origin %q has an unsupported scheme", ErrInvalidConfig, origin)
	}
}

func originHost(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("%w: origin %q has no host", ErrInvalidConfig, origin)
	}

	return strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), nil
}

func originMatchesRPID(host, rpID string, allowInsecureLocalhost bool) bool {
	rpID = strings.ToLower(strings.TrimSuffix(rpID, "."))
	if host == rpID || strings.HasSuffix(host, "."+rpID) {
		return true
	}

	// Local test mode treats every loopback spelling as the same relying party.
	return allowInsecureLocalhost && isLoopbackHost(host) &&
		(isLoopbackHost(rpID) || strings.EqualFold(rpID, "localhost"))
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateConfig re-runs configuration validation for an existing service.
func (s *Service) ValidateConfig() error {
	return s.config.Validate()
}
