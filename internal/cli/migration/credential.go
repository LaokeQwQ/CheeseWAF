package migration

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/approval"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	setupmigration "github.com/LaokeQwQ/CheeseWAF/internal/setup/migration"
	"golang.org/x/crypto/bcrypt"
)

const (
	migrationTOTPPeriod      = int64(30)
	migrationTOTPDigits      = 6
	migrationTOTPConsumedTTL = 2 * time.Minute
)

type credentialAuthorization struct {
	actor     string
	sessionID string
	password  bool
	totp      bool
	state     *credentialAuthorizationState
}

type credentialAuthorizationState struct {
	mu        sync.Mutex
	db        *sql.DB
	consumed  bool
	confirmed bool
	confirmID string
}

type credentialConfirmationProvider struct {
	authorization  credentialAuthorization
	confirmationID string
}

func verifyCredential(ctx context.Context, db *sql.DB, actor, sessionID string, secret []byte, passwordMode bool, now time.Time) (credentialAuthorization, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if db == nil || approval.ValidateIdentifier(actor) != nil || approval.ValidateIdentifier(sessionID) != nil || len(secret) == 0 {
		return credentialAuthorization{}, ErrCredentialRejected
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return credentialAuthorization{}, ErrCredentialRejected
	}
	defer func() { _ = tx.Rollback() }()

	var passwordHash, totpSecret string
	var totpEnabled int
	err = tx.QueryRowContext(ctx, `
		SELECT u.password_hash, u.two_fa_enabled, u.two_fa_secret
		FROM users AS u
		JOIN admin_sessions AS s
		  ON s.user_id=u.id
		 AND s.username=u.username
		 AND s.role=u.role
		 AND s.credential_epoch=u.credential_epoch
		WHERE u.id=? AND u.role='admin' AND s.id=? AND s.user_id=?
		  AND s.revoked_at='' AND s.expires_at>?`, actor, sessionID, actor, now.UTC().Format(time.RFC3339Nano)).Scan(&passwordHash, &totpEnabled, &totpSecret)
	if err != nil {
		return credentialAuthorization{}, ErrCredentialRejected
	}

	authorization := credentialAuthorization{
		actor: actor, sessionID: sessionID, password: passwordMode, totp: !passwordMode,
		state: &credentialAuthorizationState{db: db},
	}
	if passwordMode {
		if bcrypt.CompareHashAndPassword([]byte(passwordHash), secret) != nil {
			return credentialAuthorization{}, ErrCredentialRejected
		}
	} else {
		if totpEnabled != 1 || totpSecret == "" {
			return credentialAuthorization{}, ErrCredentialRejected
		}
		counter, ok := matchingMigrationTOTPCounter(totpSecret, string(secret), now)
		if !ok {
			return credentialAuthorization{}, ErrCredentialRejected
		}
		expiresAt := now.UTC().Add(migrationTOTPConsumedTTL).Format(time.RFC3339Nano)
		result, insertErr := tx.ExecContext(ctx, `
			INSERT INTO totp_consumed(user_id,counter,expires_at,created_at)
			VALUES(?,?,?,?)
			ON CONFLICT(user_id,counter) DO UPDATE SET
			  expires_at=excluded.expires_at, created_at=excluded.created_at
			WHERE totp_consumed.expires_at<=?`, actor, counter, expiresAt, now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
		if insertErr != nil {
			return credentialAuthorization{}, ErrCredentialRejected
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil || affected != 1 {
			return credentialAuthorization{}, ErrCredentialRejected
		}
	}
	if err := tx.Commit(); err != nil {
		return credentialAuthorization{}, ErrCredentialRejected
	}
	return authorization, nil
}

func (a credentialAuthorization) provider(confirmationID string) (*credentialConfirmationProvider, error) {
	if a.state == nil || approval.ValidateIdentifier(a.actor) != nil || approval.ValidateIdentifier(a.sessionID) != nil || approval.ValidateIdentifier(confirmationID) != nil || a.password == a.totp {
		return nil, ErrCredentialRejected
	}
	return &credentialConfirmationProvider{authorization: a, confirmationID: confirmationID}, nil
}

func (p *credentialConfirmationProvider) Confirm(ctx context.Context, request setupmigration.ConfirmationRequest) error {
	if p == nil || p.authorization.state == nil {
		return ErrCredentialRejected
	}
	if request.Actor != p.authorization.actor || request.SessionID != p.authorization.sessionID || request.ConfirmationID != p.confirmationID || request.PasswordConfirmed != p.authorization.password || request.TOTPConfirmed != p.authorization.totp {
		return ErrCredentialRejected
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state := p.authorization.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.consumed {
		return ErrCredentialRejected
	}
	activeAt := request.WarningReadAt.Add(setupmigration.WarningDelay)
	var active int
	err := state.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM admin_sessions AS s
		JOIN users AS u
		  ON u.id=s.user_id
		 AND u.username=s.username
		 AND u.role=s.role
		 AND u.credential_epoch=s.credential_epoch
		WHERE s.id=? AND s.user_id=? AND u.role='admin'
		  AND s.revoked_at='' AND s.expires_at>?`, request.SessionID, request.Actor, activeAt.UTC().Format(time.RFC3339Nano)).Scan(&active)
	if err != nil || active != 1 {
		return ErrCredentialRejected
	}
	state.consumed = true
	state.confirmed = true
	state.confirmID = request.ConfirmationID
	return nil
}

func (p *credentialConfirmationProvider) AuthorizeInitialState(_ context.Context, request controlplane.InitialStateRequest) error {
	if p == nil || p.authorization.state == nil || request.Confirmation.ID != p.confirmationID || request.Confirmation.Actor != p.authorization.actor || request.Nonce != p.confirmationID {
		return ErrCredentialRejected
	}
	state := p.authorization.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.confirmed || state.confirmID != p.confirmationID {
		return ErrCredentialRejected
	}
	return nil
}

func matchingMigrationTOTPCounter(secret, code string, now time.Time) (int64, bool) {
	if len(code) != migrationTOTPDigits {
		return 0, false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	counter := now.UTC().Unix() / migrationTOTPPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		step := counter + offset
		expected, err := migrationHOTP(secret, step)
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

func migrationHOTP(secret string, counter int64) (string, error) {
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(message[:]); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%0*d", migrationTOTPDigits, value%1_000_000), nil
}

func strictIdentity(value string) error {
	if err := approval.ValidateIdentifier(value); err != nil {
		return errors.New("value is required and must not contain whitespace or invisible characters")
	}
	return nil
}
