package passkey

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

func validConfig() Config {
	return Config{
		RPDisplayName: "CheeseWAF",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}
}

func TestConfigValidateRejectsInvalidPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing rp id", mutate: func(c *Config) { c.RPID = "" }},
		{name: "rp id with scheme", mutate: func(c *Config) { c.RPID = "https://example.com" }},
		{name: "missing display name", mutate: func(c *Config) { c.RPDisplayName = " " }},
		{name: "missing origins", mutate: func(c *Config) { c.RPOrigins = nil }},
		{name: "empty origin", mutate: func(c *Config) { c.RPOrigins = []string{""} }},
		{name: "plain http", mutate: func(c *Config) { c.RPOrigins = []string{"http://example.com"} }},
		{name: "http localhost without test mode", mutate: func(c *Config) {
			c.RPID = "localhost"
			c.RPOrigins = []string{"http://localhost:8080"}
		}},
		{name: "origin path", mutate: func(c *Config) { c.RPOrigins = []string{"https://example.com/path"} }},
		{name: "origin query", mutate: func(c *Config) { c.RPOrigins = []string{"https://example.com?x=1"} }},
		{name: "origin credentials", mutate: func(c *Config) { c.RPOrigins = []string{"https://user@example.com"} }},
		{name: "origin outside rp id", mutate: func(c *Config) { c.RPOrigins = []string{"https://attacker.example.net"} }},
		{name: "discouraged user verification", mutate: func(c *Config) {
			c.UserVerification = protocol.VerificationDiscouraged
		}},
		{name: "unknown user verification", mutate: func(c *Config) {
			c.UserVerification = protocol.UserVerificationRequirement("sometimes")
		}},
		{name: "negative timeout", mutate: func(c *Config) { c.Timeout = -time.Second }},
		{name: "oversized timeout", mutate: func(c *Config) { c.Timeout = MaxTimeout + time.Second }},
		{name: "negative challenge ttl", mutate: func(c *Config) { c.ChallengeTTL = -time.Second }},
		{name: "oversized challenge ttl", mutate: func(c *Config) { c.ChallengeTTL = MaxChallengeTTL + time.Second }},
		{name: "too many origins", mutate: func(c *Config) {
			c.RPOrigins = make([]string, maxRPOrigins+1)
			for i := range c.RPOrigins {
				c.RPOrigins[i] = "https://example.com"
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.mutate(&config)

			if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("Validate() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestConfigValidateAcceptsSecureAndLocalhostTestMode(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{name: "https", config: validConfig()},
		{name: "https subdomain", config: Config{
			RPDisplayName: "CheeseWAF",
			RPID:          "example.com",
			RPOrigins:     []string{"https://admin.example.com"},
		}},
		{name: "http localhost test mode", config: Config{
			RPDisplayName:          "CheeseWAF",
			RPID:                   "localhost",
			RPOrigins:              []string{"http://localhost:8080"},
			AllowInsecureLocalhost: true,
		}},
		{name: "http loopback ip test mode", config: Config{
			RPDisplayName:          "CheeseWAF",
			RPID:                   "localhost",
			RPOrigins:              []string{"http://127.0.0.1:8080"},
			AllowInsecureLocalhost: true,
		}},
		{name: "duplicate origins collapse", config: Config{
			RPDisplayName: "CheeseWAF",
			RPID:          "example.com",
			RPOrigins:     []string{"https://example.com", "https://example.com"},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			normalized, err := test.config.normalized()
			if err != nil {
				t.Fatalf("normalized() error = %v", err)
			}

			if normalized.UserVerification != protocol.VerificationRequired {
				t.Fatalf("UserVerification = %q, want required default", normalized.UserVerification)
			}

			if normalized.Timeout != DefaultTimeout {
				t.Fatalf("Timeout = %s, want %s", normalized.Timeout, DefaultTimeout)
			}

			if normalized.ChallengeTTL != DefaultChallengeTTL {
				t.Fatalf("ChallengeTTL = %s, want %s", normalized.ChallengeTTL, DefaultChallengeTTL)
			}

			if len(normalized.RPOrigins) != 1 {
				t.Fatalf("RPOrigins = %v, want deduplicated single origin", normalized.RPOrigins)
			}
		})
	}
}

func TestNewServiceRequiresStoreAndStrongKey(t *testing.T) {
	if _, err := NewService(validConfig(), Options{SessionKey: []byte(strings.Repeat("k", MinSessionKeyLen))}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store error = %v, want ErrInvalidConfig", err)
	}

	if _, err := NewService(validConfig(), Options{Store: newMemoryStore(), SessionKey: []byte("short")}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short key error = %v, want ErrInvalidConfig", err)
	}

	service, err := NewService(validConfig(), Options{Store: newMemoryStore(), SessionKey: []byte(strings.Repeat("k", MinSessionKeyLen))})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	if err := service.ValidateConfig(); err != nil {
		t.Fatalf("ValidateConfig() error = %v", err)
	}

	if service.Config().RPOrigins[0] != "https://example.com" {
		t.Fatalf("Config() origins = %v", service.Config().RPOrigins)
	}
}
