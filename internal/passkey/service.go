package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// MinSessionKeyLen is the minimum HMAC key length accepted for challenge
// tokens.
const MinSessionKeyLen = 32

// Options configures a Service. Store and SessionKey are required.
type Options struct {
	Store      Store
	SessionKey []byte
	// Now defaults to time.Now.
	Now func() time.Time
	// Random defaults to crypto/rand.Reader.
	Random io.Reader
	// ReplayGuard defaults to a bounded in-process MemoryReplayGuard, which
	// does not share state across processes or restarts. Inject a durable
	// implementation when replay protection must span either.
	ReplayGuard ReplayGuard
}

// Service runs WebAuthn ceremonies against a Store using signed challenge
// session tokens.
type Service struct {
	config     Config
	wa         *webauthn.WebAuthn
	store      Store
	sessionKey []byte
	now        func() time.Time
	random     io.Reader
	replay     ReplayGuard
}

// NewService validates the Relying Party configuration and constructs a
// Service. A nil store, a short session key, or an invalid origin policy is
// rejected.
func NewService(config Config, options Options) (*Service, error) {
	normalized, err := config.normalized()
	if err != nil {
		return nil, err
	}

	if options.Store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}

	if len(options.SessionKey) < MinSessionKeyLen {
		return nil, fmt.Errorf("%w: session key must be at least %d bytes", ErrInvalidConfig, MinSessionKeyLen)
	}

	waConfig := &webauthn.Config{
		RPDisplayName: normalized.RPDisplayName,
		RPID:          normalized.RPID,
		RPOrigins:     append([]string(nil), normalized.RPOrigins...),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   normalized.UserVerification,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: new(true),
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    normalized.Timeout,
				TimeoutUVD: normalized.Timeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    normalized.Timeout,
				TimeoutUVD: normalized.Timeout,
			},
		},
		AttestationPreference: protocol.PreferNoAttestation,
	}

	wa, err := webauthn.New(waConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	random := options.Random
	if random == nil {
		random = rand.Reader
	}

	replay := options.ReplayGuard
	if replay == nil {
		replay = NewMemoryReplayGuard(0)
	}

	return &Service{
		config:     normalized,
		wa:         wa,
		store:      options.Store,
		sessionKey: append([]byte(nil), options.SessionKey...),
		now:        now,
		random:     random,
		replay:     replay,
	}, nil
}

// Config returns a copy of the normalized configuration.
func (s *Service) Config() Config {
	copied := s.config
	copied.RPOrigins = append([]string(nil), s.config.RPOrigins...)
	return copied
}

// BeginRegistration creates credential creation options and a signed,
// single-use session token.
func (s *Service) BeginRegistration(ctx context.Context, user User) (*protocol.CredentialCreation, string, error) {
	if err := validateUser(user); err != nil {
		return nil, "", err
	}

	_, credentials, err := s.loadCredentials(ctx, user.ID)
	if err != nil {
		return nil, "", err
	}

	adapter := &webAuthnUser{user: user, credentials: credentials}

	creation, session, err := s.wa.BeginRegistration(adapter, webauthn.WithExclusions(webauthn.Credentials(credentials).CredentialDescriptors()))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin registration: %w", err)
	}

	now := s.now()
	expiresAt := now.Add(s.config.ChallengeTTL)
	session.Expires = expiresAt

	tokenID, err := s.newTokenID()
	if err != nil {
		return nil, "", err
	}

	token, err := s.sealSession(sessionEnvelope{
		ceremony:  CeremonyRegistration,
		issuedAt:  now,
		expiresAt: expiresAt,
		tokenID:   tokenID,
		userID:    user.ID,
		session:   session,
	})
	if err != nil {
		return nil, "", err
	}

	return creation, token, nil
}

// FinishRegistration verifies the authenticator response and persists the
// credential. The supplied token is consumed before verification.
func (s *Service) FinishRegistration(ctx context.Context, user User, sessionToken string, response *http.Request) (*Credential, error) {
	if err := validateUser(user); err != nil {
		return nil, err
	}

	if response == nil {
		return nil, fmt.Errorf("%w: missing authenticator response", ErrInvalidUser)
	}

	session, err := s.openSession(ctx, sessionToken, CeremonyRegistration, user.ID)
	if err != nil {
		return nil, err
	}

	_, credentials, err := s.loadCredentials(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	adapter := &webAuthnUser{user: user, credentials: credentials}

	registered, err := s.wa.FinishRegistration(adapter, *session, response)
	if err != nil {
		return nil, fmt.Errorf("passkey: finish registration: %w", err)
	}

	model, err := credentialFromWebAuthn(user, registered, s.now())
	if err != nil {
		return nil, err
	}

	if _, err := s.store.GetByCredentialID(ctx, model.CredentialID); err == nil {
		return nil, ErrCredentialExists
	} else if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("passkey: lookup credential: %w", err)
	}

	if err := s.store.Create(ctx, model); err != nil {
		if errors.Is(err, ErrCredentialExists) {
			return nil, ErrCredentialExists
		}

		return nil, fmt.Errorf("passkey: create credential: %w", err)
	}

	return model, nil
}

// BeginLogin creates assertion options and a signed, single-use session token.
func (s *Service) BeginLogin(ctx context.Context, user User) (*protocol.CredentialAssertion, string, error) {
	if err := validateUser(user); err != nil {
		return nil, "", err
	}

	_, credentials, err := s.loadCredentials(ctx, user.ID)
	if err != nil {
		return nil, "", err
	}

	if len(credentials) == 0 {
		return nil, "", ErrNoCredentials
	}

	adapter := &webAuthnUser{user: user, credentials: credentials}

	assertion, session, err := s.wa.BeginLogin(adapter)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin login: %w", err)
	}

	now := s.now()
	expiresAt := now.Add(s.config.ChallengeTTL)
	session.Expires = expiresAt

	tokenID, err := s.newTokenID()
	if err != nil {
		return nil, "", err
	}

	token, err := s.sealSession(sessionEnvelope{
		ceremony:  CeremonyLogin,
		issuedAt:  now,
		expiresAt: expiresAt,
		tokenID:   tokenID,
		userID:    user.ID,
		session:   session,
	})
	if err != nil {
		return nil, "", err
	}

	return assertion, token, nil
}

// FinishLogin verifies the assertion, advances the stored signature counter,
// and records the last-used time. The supplied token is consumed before
// verification.
func (s *Service) FinishLogin(ctx context.Context, user User, sessionToken string, response *http.Request) (*Credential, error) {
	if err := validateUser(user); err != nil {
		return nil, err
	}

	if response == nil {
		return nil, fmt.Errorf("%w: missing authenticator response", ErrInvalidUser)
	}

	session, err := s.openSession(ctx, sessionToken, CeremonyLogin, user.ID)
	if err != nil {
		return nil, err
	}

	records, credentials, err := s.loadCredentials(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	if len(credentials) == 0 {
		return nil, ErrNoCredentials
	}

	adapter := &webAuthnUser{user: user, credentials: credentials}

	verified, err := s.wa.FinishLogin(adapter, *session, response)
	if err != nil {
		return nil, fmt.Errorf("passkey: finish login: %w", err)
	}
	if verified.Authenticator.CloneWarning {
		return nil, ErrCloneWarning
	}

	var stored *Credential

	for _, record := range records {
		if bytes.Equal(record.CredentialID, verified.ID) {
			stored = record
			break
		}
	}

	if stored == nil {
		return nil, fmt.Errorf("%w: verified credential is not stored", ErrInvalidCredential)
	}

	now := s.now()
	signCount := verified.Authenticator.SignCount
	if stored.SignCount != 0 && signCount <= stored.SignCount {
		return nil, ErrCloneWarning
	}

	if err := s.store.UpdateSignCount(ctx, stored.ID, signCount, now); err != nil {
		return nil, fmt.Errorf("passkey: update sign count: %w", err)
	}

	stored.SignCount = signCount
	stored.LastUsedAt = now

	return stored, nil
}

func (s *Service) loadCredentials(ctx context.Context, userID string) ([]*Credential, []webauthn.Credential, error) {
	records, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("passkey: list credentials: %w", err)
	}

	credentials := make([]webauthn.Credential, 0, len(records))
	out := make([]*Credential, 0, len(records))

	for _, record := range records {
		if record == nil {
			return nil, nil, fmt.Errorf("%w: nil credential record", ErrInvalidCredential)
		}

		if record.UserID != userID {
			return nil, nil, fmt.Errorf("%w: credential belongs to another user", ErrInvalidCredential)
		}

		credential, err := toWebAuthnCredential(record)
		if err != nil {
			return nil, nil, err
		}

		credentials = append(credentials, credential)
		out = append(out, record)
	}

	return out, credentials, nil
}

func (s *Service) newTokenID() ([sessionTokenIDLen]byte, error) {
	var id [sessionTokenIDLen]byte

	if _, err := io.ReadFull(s.random, id[:]); err != nil {
		return id, fmt.Errorf("%w: cannot generate token ID: %v", ErrInvalidSessionToken, err)
	}

	return id, nil
}
