package passkey

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Ceremony identifies which WebAuthn ceremony a signed session belongs to.
// Binding the ceremony prevents a registration token from being replayed at
// the login endpoint and vice versa.
type Ceremony byte

const (
	CeremonyRegistration Ceremony = 1
	CeremonyLogin        Ceremony = 2

	sessionTokenVersion         byte = 1
	sessionTokenHeaderLen            = 1 + 1 + 8 + 8 + 16 + 2
	sessionTokenIDLen                = 16
	sessionTokenMaxRawBytes          = 64 << 10
	sessionTokenMaxEncodedBytes      = 128 << 10
	sessionTokenClockSkew            = 30 * time.Second
	sessionMACDomain                 = "cheesewaf/passkey/session-token/v1\x00"
)

func (c Ceremony) String() string {
	switch c {
	case CeremonyRegistration:
		return "registration"
	case CeremonyLogin:
		return "login"
	default:
		return "unknown"
	}
}

// sessionEnvelope is the cleartext content covered by the token MAC.
type sessionEnvelope struct {
	ceremony  Ceremony
	issuedAt  time.Time
	expiresAt time.Time
	tokenID   [sessionTokenIDLen]byte
	userID    string
	session   *webauthn.SessionData
}

// sealSession serializes SessionData and an envelope into an opaque, signed
// token. The token is the only challenge state a caller needs to persist
// between Begin and Finish.
func (s *Service) sealSession(envelope sessionEnvelope) (string, error) {
	if envelope.session == nil {
		return "", fmt.Errorf("%w: missing session data", ErrInvalidSessionToken)
	}

	if err := validateUserID(envelope.userID); err != nil {
		return "", err
	}

	if envelope.issuedAt.IsZero() || envelope.expiresAt.IsZero() {
		return "", fmt.Errorf("%w: missing token timestamps", ErrInvalidSessionToken)
	}

	if !envelope.expiresAt.After(envelope.issuedAt) {
		return "", fmt.Errorf("%w: token expiry must follow issuance", ErrInvalidSessionToken)
	}

	payload, err := envelope.session.MarshalMsg(nil)
	if err != nil {
		return "", fmt.Errorf("%w: cannot encode session data: %v", ErrInvalidSessionToken, err)
	}

	if len(payload) == 0 || len(payload) > MaxSessionPayloadLen {
		return "", fmt.Errorf("%w: session data must be 1..%d bytes", ErrInvalidSessionToken, MaxSessionPayloadLen)
	}

	userID := []byte(envelope.userID)
	bodyLen := sessionTokenHeaderLen + len(userID) + 4 + len(payload)
	if bodyLen+sha256.Size > sessionTokenMaxRawBytes {
		return "", fmt.Errorf("%w: token exceeds size limit", ErrInvalidSessionToken)
	}

	body := make([]byte, bodyLen)
	body[0] = sessionTokenVersion
	body[1] = byte(envelope.ceremony)
	binary.BigEndian.PutUint64(body[2:10], uint64(envelope.issuedAt.UnixNano()))
	binary.BigEndian.PutUint64(body[10:18], uint64(envelope.expiresAt.UnixNano()))
	copy(body[18:34], envelope.tokenID[:])
	binary.BigEndian.PutUint16(body[34:36], uint16(len(userID)))
	copy(body[36:], userID)

	offset := 36 + len(userID)
	binary.BigEndian.PutUint32(body[offset:offset+4], uint32(len(payload)))
	copy(body[offset+4:], payload)

	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(sessionMACDomain))
	mac.Write(body)

	raw := make([]byte, 0, len(body)+sha256.Size)
	raw = append(raw, body...)
	raw = mac.Sum(raw)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// openSession verifies, expires, and atomically consumes a signed token. A
// token is burned before the authenticator response is verified so a failed or
// replayed response can never be retried.
func (s *Service) openSession(ctx context.Context, token string, ceremony Ceremony, userID string) (*webauthn.SessionData, error) {
	if token == "" || len(token) > sessionTokenMaxEncodedBytes {
		return nil, fmt.Errorf("%w: token is empty or oversized", ErrInvalidSessionToken)
	}

	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: token is not base64url", ErrInvalidSessionToken)
	}

	if len(raw) > sessionTokenMaxRawBytes {
		return nil, fmt.Errorf("%w: token is oversized", ErrInvalidSessionToken)
	}

	if len(raw) < sessionTokenHeaderLen+4+1+sha256.Size {
		return nil, fmt.Errorf("%w: token is truncated", ErrInvalidSessionToken)
	}

	body := raw[:len(raw)-sha256.Size]
	providedMAC := raw[len(raw)-sha256.Size:]

	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write([]byte(sessionMACDomain))
	mac.Write(body)

	if !hmac.Equal(mac.Sum(nil), providedMAC) {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidSessionToken)
	}

	if body[0] != sessionTokenVersion {
		return nil, fmt.Errorf("%w: unsupported token version", ErrInvalidSessionToken)
	}

	envelope := sessionEnvelope{
		ceremony:  Ceremony(body[1]),
		issuedAt:  time.Unix(0, int64(binary.BigEndian.Uint64(body[2:10]))),
		expiresAt: time.Unix(0, int64(binary.BigEndian.Uint64(body[10:18]))),
	}
	copy(envelope.tokenID[:], body[18:34])

	userIDLen := int(binary.BigEndian.Uint16(body[34:36]))
	offset := 36
	if userIDLen == 0 || userIDLen > MaxUserIDLen || offset+userIDLen+4 > len(body) {
		return nil, fmt.Errorf("%w: invalid user ID field", ErrInvalidSessionToken)
	}

	envelope.userID = string(body[offset : offset+userIDLen])
	offset += userIDLen

	payloadLen := int(binary.BigEndian.Uint32(body[offset : offset+4]))
	offset += 4
	if payloadLen == 0 || payloadLen > MaxSessionPayloadLen || offset+payloadLen != len(body) {
		return nil, fmt.Errorf("%w: invalid payload length", ErrInvalidSessionToken)
	}

	now := s.now()

	if !envelope.expiresAt.After(now) {
		return nil, fmt.Errorf("%w: token expired at %s", ErrSessionExpired, envelope.expiresAt.UTC().Format(time.RFC3339))
	}

	if envelope.issuedAt.After(now.Add(sessionTokenClockSkew)) {
		return nil, fmt.Errorf("%w: token issued in the future", ErrInvalidSessionToken)
	}

	if envelope.ceremony != ceremony {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrCeremonyMismatch, ceremony, envelope.ceremony)
	}

	if subtle.ConstantTimeCompare([]byte(envelope.userID), []byte(userID)) != 1 {
		return nil, fmt.Errorf("%w: token belongs to another user", ErrUserMismatch)
	}

	session := new(webauthn.SessionData)
	rest, err := session.UnmarshalMsg(body[offset : offset+payloadLen])
	if err != nil {
		return nil, fmt.Errorf("%w: cannot decode session data: %v", ErrInvalidSessionToken, err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: trailing session data", ErrInvalidSessionToken)
	}

	if session.Challenge == "" {
		return nil, fmt.Errorf("%w: session has no challenge", ErrInvalidSessionToken)
	}

	consumed, err := s.replay.Consume(envelope.tokenID, now, envelope.expiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: replay check failed: %v", ErrInvalidSessionToken, err)
	}

	if !consumed {
		return nil, ErrSessionReplayed
	}

	return session, nil
}
