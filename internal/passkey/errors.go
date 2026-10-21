package passkey

import "errors"

var (
	// ErrCloneWarning rejects an assertion whose signature counter did not
	// advance. It is the WebAuthn clone signal and must never authenticate.
	ErrCloneWarning = errors.New("passkey: authenticator clone warning")
	// ErrInvalidConfig reports a Relying Party or service configuration fault.
	ErrInvalidConfig = errors.New("passkey: invalid config")
	// ErrInvalidUser reports a missing, oversized, or malformed user identity.
	ErrInvalidUser = errors.New("passkey: invalid user")
	// ErrInvalidCredential reports a credential record that cannot be trusted.
	ErrInvalidCredential = errors.New("passkey: invalid credential")
	// ErrInvalidSessionToken reports a malformed, tampered, or wrongly signed
	// challenge session token.
	ErrInvalidSessionToken = errors.New("passkey: invalid session token")
	// ErrSessionExpired reports a challenge session past its TTL.
	ErrSessionExpired = errors.New("passkey: session expired")
	// ErrSessionReplayed reports reuse of a challenge session token.
	ErrSessionReplayed = errors.New("passkey: session already used")
	// ErrCeremonyMismatch reports a token issued for the other ceremony.
	ErrCeremonyMismatch = errors.New("passkey: ceremony mismatch")
	// ErrUserMismatch reports a token issued for a different user.
	ErrUserMismatch = errors.New("passkey: user mismatch")
	// ErrNoCredentials reports a login attempt for a user without credentials.
	ErrNoCredentials = errors.New("passkey: user has no credentials")
	// ErrCredentialExists reports a credential ID that is already registered.
	ErrCredentialExists = errors.New("passkey: credential already registered")
	// ErrNotFound reports a missing store record.
	ErrNotFound = errors.New("passkey: not found")
	// ErrInvalidRecoveryCode reports a malformed or already consumed recovery code.
	ErrInvalidRecoveryCode = errors.New("passkey: invalid recovery code")
	// ErrReplayGuardFull reports a replay guard that cannot record another token
	// without exceeding its bound. The ceremony is rejected as a precaution.
	ErrReplayGuardFull = errors.New("passkey: replay guard capacity exhausted")
)
