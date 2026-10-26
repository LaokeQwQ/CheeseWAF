package passkey

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	// DefaultRecoveryCodeCount is the number of codes issued when none is
	// requested.
	DefaultRecoveryCodeCount = 10
	// MaxRecoveryCodes bounds a single issuance.
	MaxRecoveryCodes = 20

	recoveryCodeLength   = 16
	recoveryCodeGroup    = 4
	recoveryAlphabet     = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	recoveryHashDomain   = "cheesewaf/passkey/recovery-code/v1\x00"
	maxAuditActorLength  = 128
	maxAuditReasonLength = 512
)

// ResetResult reports the outcome of an administrative passkey reset.
type ResetResult struct {
	UserID               string
	CredentialsDeleted   int
	RecoveryCodesDeleted bool
	AuditRecordedAt      time.Time
}

// GenerateRecoveryCodes issues one-time recovery codes and stores only their
// SHA-256 hashes. The plaintext codes are returned exactly once.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, userID string, count int) ([]string, error) {
	if err := validateUserID(userID); err != nil {
		return nil, err
	}

	if count == 0 {
		count = DefaultRecoveryCodeCount
	}

	if count < 1 || count > MaxRecoveryCodes {
		return nil, fmt.Errorf("%w: recovery code count must be 1..%d", ErrInvalidRecoveryCode, MaxRecoveryCodes)
	}

	codes := make([]string, 0, count)
	hashes := make([][]byte, 0, count)
	seen := make(map[string]struct{}, count)

	for range count {
		issued := false

		for range 8 {
			raw := make([]byte, recoveryCodeLength)
			if _, err := io.ReadFull(s.random, raw); err != nil {
				return nil, fmt.Errorf("%w: cannot generate recovery codes: %v", ErrInvalidRecoveryCode, err)
			}

			var normalized strings.Builder
			normalized.Grow(recoveryCodeLength)

			for _, b := range raw {
				normalized.WriteByte(recoveryAlphabet[int(b)&31])
			}

			code := normalized.String()
			if _, ok := seen[code]; ok {
				continue
			}

			seen[code] = struct{}{}
			codes = append(codes, formatRecoveryCode(code))
			hashes = append(hashes, hashRecoveryCode(code))
			issued = true

			break
		}

		if !issued {
			return nil, fmt.Errorf("%w: cannot generate a unique recovery code", ErrInvalidRecoveryCode)
		}
	}

	if err := s.store.ReplaceRecoveryCodes(ctx, userID, hashes, s.now()); err != nil {
		return nil, fmt.Errorf("passkey: store recovery codes: %w", err)
	}

	return codes, nil
}

// ConsumeRecoveryCode normalizes a presented code and atomically consumes its
// hash. It reports false without an error when the code is unknown, already
// used, or belongs to another user.
func (s *Service) ConsumeRecoveryCode(ctx context.Context, userID, code string) (bool, error) {
	if err := validateUserID(userID); err != nil {
		return false, err
	}

	normalized, err := normalizeRecoveryCode(code)
	if err != nil {
		return false, err
	}

	consumed, err := s.store.ConsumeRecoveryCode(ctx, userID, hashRecoveryCode(normalized), s.now())
	if err != nil {
		return false, fmt.Errorf("passkey: consume recovery code: %w", err)
	}

	return consumed, nil
}

// AdminReset removes every credential and recovery code for a user and
// records an audit event. It is deliberately separate from ceremony handling
// and has no UI.
func (s *Service) AdminReset(ctx context.Context, userID, actor, reason string) (ResetResult, error) {
	var result ResetResult

	if err := validateUserID(userID); err != nil {
		return result, err
	}

	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)

	if actor == "" || len(actor) > maxAuditActorLength {
		return result, fmt.Errorf("%w: actor must be 1..%d bytes", ErrInvalidUser, maxAuditActorLength)
	}

	if reason == "" || len(reason) > maxAuditReasonLength {
		return result, fmt.Errorf("%w: reason must be 1..%d bytes", ErrInvalidUser, maxAuditReasonLength)
	}

	records, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return result, fmt.Errorf("passkey: list credentials for reset: %w", err)
	}

	if err := s.store.DeleteByUser(ctx, userID); err != nil {
		return result, fmt.Errorf("passkey: delete credentials: %w", err)
	}

	if err := s.store.DeleteRecoveryCodes(ctx, userID); err != nil {
		return result, fmt.Errorf("passkey: delete recovery codes: %w", err)
	}

	now := s.now()
	if err := s.store.RecordAudit(ctx, AuditEvent{
		Type:   "passkey.admin_reset",
		UserID: userID,
		Actor:  actor,
		Reason: reason,
		At:     now,
	}); err != nil {
		return result, fmt.Errorf("passkey: record reset audit: %w", err)
	}

	result.UserID = userID
	result.CredentialsDeleted = len(records)
	result.RecoveryCodesDeleted = true
	result.AuditRecordedAt = now

	return result, nil
}

func formatRecoveryCode(normalized string) string {
	var out strings.Builder
	out.Grow(recoveryCodeLength + recoveryCodeLength/recoveryCodeGroup - 1)

	for i, r := range normalized {
		if i > 0 && i%recoveryCodeGroup == 0 {
			out.WriteByte('-')
		}

		out.WriteRune(r)
	}

	return out.String()
}

func normalizeRecoveryCode(code string) (string, error) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return "", fmt.Errorf("%w: code is empty", ErrInvalidRecoveryCode)
	}

	var normalized strings.Builder
	normalized.Grow(recoveryCodeLength)

	for _, r := range code {
		switch r {
		case '-', ' ':
			continue
		}

		if !strings.ContainsRune(recoveryAlphabet, r) {
			return "", fmt.Errorf("%w: code contains invalid characters", ErrInvalidRecoveryCode)
		}

		normalized.WriteRune(r)
	}

	if normalized.Len() != recoveryCodeLength {
		return "", fmt.Errorf("%w: code must be %d characters", ErrInvalidRecoveryCode, recoveryCodeLength)
	}

	return normalized.String(), nil
}

func hashRecoveryCode(normalized string) []byte {
	sum := sha256.Sum256([]byte(recoveryHashDomain + normalized))
	return append([]byte(nil), sum[:]...)
}
