package passkey

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	// MaxUserIDLen is the WebAuthn user handle limit (§5.4.3).
	MaxUserIDLen = 64
	// MaxCredentialIDLen bounds a raw credential ID accepted from a store.
	MaxCredentialIDLen = 1024
	// MaxPublicKeyLen bounds a COSE public key accepted from a store.
	MaxPublicKeyLen = 16 << 10
	// MaxSessionPayloadLen bounds the encoded SessionData inside a token.
	MaxSessionPayloadLen = 32 << 10
	// MaxCredentialNameLen bounds the human-readable credential label.
	MaxCredentialNameLen = 128
	// DefaultCredentialName is used when a caller does not label a new passkey.
	DefaultCredentialName = "Passkey"
)

// Credential is the storage projection of a WebAuthn credential. Only the
// public key and metadata are retained; private keys never leave the
// authenticator.
type Credential struct {
	// ID is the stable storage identifier for this credential record.
	ID string
	// UserID is the account identifier that owns the credential.
	UserID string
	// CredentialID is the raw WebAuthn credential ID.
	CredentialID []byte
	// PublicKey is the COSE-encoded credential public key.
	PublicKey []byte
	// SignCount is the last accepted authenticator signature counter.
	SignCount uint32
	// Transports lists authenticator transports reported at registration.
	Transports []string
	// AAGUID is the authenticator model identifier (16 bytes when present).
	AAGUID []byte
	// BackupEligible reports whether the credential can be synced or backed up.
	BackupEligible bool
	CreatedAt      time.Time
	LastUsedAt     time.Time
	// Name is the operator-visible label for this credential.
	Name string
}

// Validate checks the bounds this package relies on before signing or
// verifying with a credential record.
func (c Credential) Validate() error {
	if c.ID == "" || len(c.ID) > 2*MaxCredentialIDLen {
		return fmt.Errorf("%w: credential record ID is empty or too long", ErrInvalidCredential)
	}

	if err := validateUserID(c.UserID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCredential, err)
	}

	if len(c.CredentialID) == 0 || len(c.CredentialID) > MaxCredentialIDLen {
		return fmt.Errorf("%w: credential ID must be 1..%d bytes", ErrInvalidCredential, MaxCredentialIDLen)
	}

	if len(c.PublicKey) == 0 || len(c.PublicKey) > MaxPublicKeyLen {
		return fmt.Errorf("%w: public key must be 1..%d bytes", ErrInvalidCredential, MaxPublicKeyLen)
	}

	if len(c.AAGUID) != 0 && len(c.AAGUID) != 16 {
		return fmt.Errorf("%w: AAGUID must be empty or 16 bytes", ErrInvalidCredential)
	}

	if len(c.Transports) > 10 {
		return fmt.Errorf("%w: too many transports", ErrInvalidCredential)
	}

	for _, transport := range c.Transports {
		if transport == "" || len(transport) > 32 {
			return fmt.Errorf("%w: invalid transport", ErrInvalidCredential)
		}
	}

	if c.Name == "" || len(c.Name) > MaxCredentialNameLen || strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("%w: credential name must be 1..%d bytes", ErrInvalidCredential, MaxCredentialNameLen)
	}

	return nil
}

// AuditEvent is an append-only administrative audit record. Actor and Reason
// are mandatory for destructive passkey administration.
type AuditEvent struct {
	Type   string
	UserID string
	Actor  string
	Reason string
	At     time.Time
}

// Store persists credentials, recovery-code hashes, and audit events. Every
// method is expected to be safe for concurrent use. Implementations MUST make
// ConsumeRecoveryCode atomic and MUST return ErrNotFound for missing records.
type Store interface {
	ListByUser(ctx context.Context, userID string) ([]*Credential, error)
	GetByCredentialID(ctx context.Context, credentialID []byte) (*Credential, error)
	Create(ctx context.Context, credential *Credential) error
	UpdateSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error
	Delete(ctx context.Context, id string) error
	DeleteByUser(ctx context.Context, userID string) error

	// ReplaceRecoveryCodes atomically replaces every recovery-code hash for the
	// user. Only hashes are ever passed to the store.
	ReplaceRecoveryCodes(ctx context.Context, userID string, hashes [][]byte, createdAt time.Time) error
	// ConsumeRecoveryCode atomically removes and reports a matching hash.
	// Implementations should compare hashes in constant time.
	ConsumeRecoveryCode(ctx context.Context, userID string, hash []byte, now time.Time) (bool, error)
	DeleteRecoveryCodes(ctx context.Context, userID string) error

	RecordAudit(ctx context.Context, event AuditEvent) error
}

// User is the caller-supplied account identity for a ceremony. ID becomes the
// WebAuthn user handle and must therefore be at most 64 bytes.
type User struct {
	ID          string
	Name        string
	DisplayName string
	// CredentialName labels a newly registered credential. Empty means
	// DefaultCredentialName.
	CredentialName string
}

func validateUser(user User) error {
	if err := validateUserID(user.ID); err != nil {
		return err
	}

	if user.Name == "" || strings.TrimSpace(user.Name) == "" || len(user.Name) > MaxCredentialNameLen {
		return fmt.Errorf("%w: name must be 1..%d bytes", ErrInvalidUser, MaxCredentialNameLen)
	}

	if len(user.DisplayName) > MaxCredentialNameLen ||
		(user.DisplayName != "" && strings.TrimSpace(user.DisplayName) == "") {
		return fmt.Errorf("%w: display name is invalid", ErrInvalidUser)
	}

	if len(user.CredentialName) > MaxCredentialNameLen ||
		(user.CredentialName != "" && strings.TrimSpace(user.CredentialName) == "") {
		return fmt.Errorf("%w: credential name is invalid", ErrInvalidUser)
	}

	return nil
}

func validateUserID(id string) error {
	if id == "" || strings.TrimSpace(id) != id {
		return fmt.Errorf("%w: user ID must be non-empty without surrounding spaces", ErrInvalidUser)
	}

	if len(id) > MaxUserIDLen {
		return fmt.Errorf("%w: user ID exceeds %d bytes", ErrInvalidUser, MaxUserIDLen)
	}

	if !utf8.ValidString(id) {
		return fmt.Errorf("%w: user ID is not valid UTF-8", ErrInvalidUser)
	}

	for _, r := range id {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: user ID contains control characters", ErrInvalidUser)
		}
	}

	return nil
}

// webAuthnUser adapts User plus stored credentials to webauthn.User.
type webAuthnUser struct {
	user        User
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.user.Name
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}

	return u.user.Name
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func toWebAuthnCredential(credential *Credential) (webauthn.Credential, error) {
	if credential == nil {
		return webauthn.Credential{}, fmt.Errorf("%w: nil credential record", ErrInvalidCredential)
	}

	if err := credential.Validate(); err != nil {
		return webauthn.Credential{}, err
	}

	transports := make([]protocol.AuthenticatorTransport, len(credential.Transports))
	for i, transport := range credential.Transports {
		transports[i] = protocol.AuthenticatorTransport(transport)
	}

	return webauthn.Credential{
		ID:        append([]byte(nil), credential.CredentialID...),
		PublicKey: append([]byte(nil), credential.PublicKey...),
		Transport: transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: credential.BackupEligible,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    append([]byte(nil), credential.AAGUID...),
			SignCount: credential.SignCount,
		},
	}, nil
}

func credentialFromWebAuthn(user User, credential *webauthn.Credential, now time.Time) (*Credential, error) {
	if credential == nil {
		return nil, fmt.Errorf("%w: nil registered credential", ErrInvalidCredential)
	}

	transports := make([]string, len(credential.Transport))
	for i, transport := range credential.Transport {
		transports[i] = string(transport)
	}

	name := user.CredentialName
	if name == "" {
		name = DefaultCredentialName
	}

	model := &Credential{
		ID:             hex.EncodeToString(credential.ID),
		UserID:         user.ID,
		CredentialID:   append([]byte(nil), credential.ID...),
		PublicKey:      append([]byte(nil), credential.PublicKey...),
		SignCount:      credential.Authenticator.SignCount,
		Transports:     transports,
		AAGUID:         append([]byte(nil), credential.Authenticator.AAGUID...),
		BackupEligible: credential.Flags.BackupEligible,
		CreatedAt:      now,
		Name:           name,
	}

	if err := model.Validate(); err != nil {
		return nil, err
	}

	return model, nil
}
